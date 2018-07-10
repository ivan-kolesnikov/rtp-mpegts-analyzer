#include "r_m_analyzer.h"

int main(int argc, char *argv[])
{
    // parse argv and set argv indexes
    argv_parser(&argc, argv);
    int sock;
    socklen_t socklen;
    struct sockaddr_in saddr;
    join_mcast(&sock, &socklen, &saddr, argv);
    std::cout << current_datetime() << " Capturing_from: " << argv[addressIndex] << ":" << argv[portIndex] << std::endl;

    int read_bytes = 0;
    int read_bytes_sum = 0;
    int rtp_header_size = 0;
    uint8_t rtp_package_buff[READ_N_BYTES_PER_ITERATION];
    int udp_error_raise_counter = 0;
    uint udp_lost_packages_counter = 0;
    uint16_t pcr_pid = 0;
    uint16_t pmt_pid = 0;
    int cc_error_raise_counter = 0;
    long int last_report_time_ms = epoch_ms();
    long int last_report_time_difference_ms = 0;
    int bitrate_kbs = 0;

    while (true)
    {
        // read data from the socket
        read_bytes = recvfrom(sock, rtp_package_buff, READ_N_BYTES_PER_ITERATION, 0, (struct sockaddr *)&saddr, &socklen);
        if (read_bytes > 0)
        {
            // sum of bytes for the bitrate calculation
            read_bytes_sum += read_bytes;
            rtp_header_size = 12 + 4 * (rtp_package_buff[0] & 16);
            // check RTP header cc
            int lost_udp_packages = check_rtp_cc(rtp_package_buff);
            // if any RTP packages were lost
            if (lost_udp_packages)
            {
                udp_lost_packages_counter += lost_udp_packages;
                udp_error_raise_counter++;
            }
            // for each ts package
            for (int ts_package_index = 0; ts_package_index < AMOUNT_TS_PACKAGES_IN_RTP_PACKAGE; ts_package_index++)
            {
                // if pcr_pid doesn't exist
                if (!pcr_pid)
                {
                    // if pmt_pid doesn't exist
                    if (!pmt_pid)
                    {
                        pmt_pid = get_pid_from_table(&rtp_package_buff[rtp_header_size + \
                                ts_package_index*DEFAULT_TS_PACKAGE_SIZE], 1, 0);
                    // try to find pcr_pid
                    } else
                    {
                        pcr_pid = get_pid_from_table(&rtp_package_buff[rtp_header_size + \
                                ts_package_index*DEFAULT_TS_PACKAGE_SIZE], 0, pmt_pid);
                    }
                // try to find cc value
                } else
                {
                    cc_error_raise_counter += check_ts_cc(&rtp_package_buff[rtp_header_size + \
                            ts_package_index*DEFAULT_TS_PACKAGE_SIZE], &pcr_pid);
                }
            }
        // reconnect in case of error
        } else if (read_bytes == -1)
        {
            sleep(1);
            leave_mcast(&sock);
            join_mcast(&sock, &socklen, &saddr, argv);
        }
        // find difference between now and the last_report_time_ms
        last_report_time_difference_ms = epoch_ms() - last_report_time_ms;
        // need to send the report
        if (last_report_time_difference_ms > 1000)
        {
            bitrate_kbs = read_bytes_sum*8/last_report_time_difference_ms*1000/1024;
            std::cout << current_datetime() << " Bitrate: " << std::to_string(bitrate_kbs) << " Kbit/s";
            if (udp_error_raise_counter)
            {
                std::cout << " UDP_errors: " << std::to_string(udp_error_raise_counter);
            }
            if (udp_lost_packages_counter)
            {
                std::cout << " UDP_lost_packages: " << std::to_string(udp_lost_packages_counter);
            }
            if (cc_error_raise_counter)
            {
                std::cout << " CC_errors: " << std::to_string(cc_error_raise_counter);
            }
            std::cout << std::endl;
            // reset variables
            read_bytes_sum = 0;
            udp_error_raise_counter = 0;
            udp_lost_packages_counter = 0;
            cc_error_raise_counter = 0;
            last_report_time_ms = epoch_ms();
            // if need to update pcr_pid
            if (lost_pcr_pid_continuously_counter > MAX_LOST_PCR_PID_CONTINUOUSLY_VALUE)
            {
                pmt_pid = 0;
                pcr_pid = 0;
            }
        }
    }
    leave_mcast(&sock);
    return 0;
}


uint16_t get_pid_from_table(uint8_t *p_ts_package, bool is_pmt_pid, uint16_t table_pid)
{
    uint32_t ts_header_dw = 0x47;
    uint16_t program_number = 0;
    uint16_t result_pid = 0;
    uint pmt_while_counter = 0;
    uint8_t byte_from_buff = 0;
    if (*p_ts_package++ == 0x47)
    {
        for (int i = 0; i < 3; i++)
        {
            byte_from_buff = *p_ts_package++;
            ts_header_dw <<=8;
            ts_header_dw += byte_from_buff;
        }
        if (!(ts_header_dw & 0x800000) && ts_header_dw & 0x400000 && (ts_header_dw & 0x1fff00)>>8 == table_pid)
        {
            p_ts_package += 9;
            if (is_pmt_pid)
            {
                while (!program_number)
                {
                    program_number += *p_ts_package++;
                    program_number <<=8;
                    program_number += *p_ts_package++;
                    if (!program_number)
                    {
                        pmt_while_counter++;
                    }
                    if (pmt_while_counter > 10)
                    {
                        return 0;
                    }
                }
            }
            result_pid = *p_ts_package++;
            result_pid <<=8;
            result_pid += *p_ts_package++;
            result_pid &= 0x1FFF;
            return result_pid;
        } else
        {
            return 0;
        }
    }
    return result_pid;
}


int check_ts_cc(uint8_t *p_ts_package, uint16_t *pid)
{
    uint32_t ts_header_dw = 0x47;
    static int8_t cc = -1;
    static int8_t ecc = -1;
    static bool cc_error_occurs = 0;
    int has_cc_error = 0;

    if (*p_ts_package++ == 0x47)
    {
        for (int i = 0; i < 3; i++)
        {
            ts_header_dw <<=8;
            ts_header_dw += *p_ts_package++;
        }
        uint8_t discontinuity_indicator = 0;
        // if discontinuity indicator exists
        if (ts_header_dw & 0x20 && *p_ts_package++) {
            // 0x20 10 – adaptation field only, no payload,11 – adaptation field followed by payload,
            discontinuity_indicator = *p_ts_package & 0x80;
        }
        if (ts_header_dw & 0x10 && (ts_header_dw & 0x1fff00)>>8 == *pid && !discontinuity_indicator)
        {
            if (cc == -1 || discontinuity_indicator)
            {
                ecc = ts_header_dw & 0xf;
            }
            cc = ts_header_dw & 0xf;
            if (ecc != cc)
            {
                if (!cc_error_occurs)
                {
                    cc_error_occurs = 1;
                } else
                {
                    has_cc_error = 1;
                    ecc = cc+1;
                    if (ecc > 15)
                    {
                        ecc = 0;
                    }
                }
            } else
            {
                cc_error_occurs = 0;
                ecc++;
                if (ecc > 15)
                {
                    ecc = 0;
                }
            }
            lost_pcr_pid_continuously_counter = 0;
        } else
        {
            lost_pcr_pid_continuously_counter++;
        }
    }
    return has_cc_error;
}


int check_rtp_cc(uint8_t *p_rtp_package)
{
    static uint16_t eseq = 0;
    uint16_t seq = 0;
    // found rtp counter and check the order
    seq = (*(p_rtp_package+2) << 8) + *(p_rtp_package+3);
    if (!eseq && seq)
    {
        eseq = seq;
    } else
    {
        eseq++;
    }
    if (seq != eseq)
    {
        int delta_seq_eseq = (seq-eseq);
        if (delta_seq_eseq < 0)
        {
            delta_seq_eseq = delta_seq_eseq + 65535;
        }
        eseq = seq;
        return delta_seq_eseq;
    }
    return 0;
}


void argv_parser(int *argc, char *argv[])
{
    for (int i = 1; i < *argc-1; i++)
    {
        if (std::string(argv[i]) == "-a" || std::string(argv[i]) == "--address-mcast")
        {
            addressIndex = ++i;
        }
        else if (std::string(argv[i]) == "-p" || std::string(argv[i]) == "--port-mcast")
        {
            portIndex = ++i;
        }
        else if (std::string(argv[i]) == "-i" || std::string(argv[i]) == "--channel-id")
        {
            idIndex = ++i;
        }
        else if (std::string(argv[i]) == "-n" || std::string(argv[i]) == "--channel-name")
        {
            nameIndex = ++i;
        }
        else
        {
            help();
            exit(1);
        }
    }
}


void help()
{
    std::cout << "r_m_analyzer" << "[options]" << std::endl
              << "Options:" << std::endl
              << "-a | --address-mcast       multicast address" << std::endl
              << "-p | --port-mcast          multicast port" << std::endl
              << "-i | --channel-id          channel id" << std::endl
              << "-n | --channel-name        channel name" << std::endl
              << "-h | --help                print this help" << std::endl;
}


void join_mcast(int *sock, socklen_t *socklen, struct sockaddr_in *saddr, char *argv[])
{
    int status;
    struct ip_mreq imreq;
    // set content of struct saddr and imreq to zero
    memset(saddr, 0, sizeof(struct sockaddr_in));
    memset(&imreq, 0, sizeof(struct ip_mreq));
    // open the UDP socket
    *sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*sock < 0)
    {
        std::cerr << "Error creating socket" << std::endl;
        exit(1);
    }
    int enable = 1;
    status = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    saddr->sin_family = PF_INET;
    // listen port
    saddr->sin_port = htons(atoi(argv[portIndex]));
    saddr->sin_addr.s_addr = inet_addr(argv[addressIndex]);
    status = bind(*sock, (struct sockaddr *)saddr, sizeof(struct sockaddr_in));
    if (status < 0)
    {
        std::cerr << "Error binding socket to interface" << std::endl;
        exit(1);
    }
    imreq.imr_multiaddr.s_addr = inet_addr(argv[addressIndex]);
    // use DEFAULT interface
    imreq.imr_interface.s_addr = INADDR_ANY;
    // JOIN multicast group on the default interface
    status = setsockopt(*sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const void *)&imreq, sizeof(struct ip_mreq));
    // set time to live for the socket
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000; // 0.1 sec
    status = setsockopt (*sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof (timeout));
    *socklen = sizeof(struct sockaddr_in);
}


void leave_mcast(int *sock)
{
    // shutdown socket
    shutdown(*sock, 2);
    // close socket
    close(*sock);
}


const std::string current_datetime()
{
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}


long int epoch_ms()
{
    static struct timeval tp;
    gettimeofday(&tp, NULL);
    return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}
