#ifndef HEADER_HPP
#define HEADER_HPP

#include <algorithm>
#include <iostream>
#include <boost/asio/ip/address.hpp>

namespace nettool {
using byte_type = unsigned char;
using size_type = std::size_t;

// ICMP header for both IPv4 and IPv6.
//
// The wire format of an ICMP header is:
// 
// 0               8               16                             31
// +---------------+---------------+------------------------------+      ---
// |               |               |                              |       ^
// |     type      |     code      |          checksum            |       |
// |               |               |                              |       |
// +---------------+---------------+------------------------------+    8 bytes
// |                               |                              |       |
// |          identifier           |       sequence number        |       |
// |                               |                              |       v
// +-------------------------------+------------------------------+      ---

class icmp_header {
public:
  enum {
    echo_reply              = 0,
    destination_unreachable = 3,
    source_quench           = 4,
    redirect                = 5,
    echo_request            = 8,
    time_exceeded           = 11,
    parameter_problem       = 12,
    timestamp_request       = 13,
    timestamp_reply         = 14,
    info_request            = 15,
    info_reply              = 16,
    address_request         = 17,
    address_reply           = 18
  };

  icmp_header() { std::fill(rep_, rep_ + 8, 0); }

  byte_type type() const { return rep_[0]; }
  byte_type code() const { return rep_[1]; }
  unsigned short checksum() const { return decode(2, 3); }
  unsigned short identifier() const { return decode(4, 5); }
  unsigned short sequence_number() const { return decode(6, 7); }

  void type(byte_type n) { rep_[0] = n; }
  void code(byte_type n) { rep_[1] = n; }
  void checksum(unsigned short n) { encode(2, 3, n); }
  void identifier(unsigned short n) { encode(4, 5, n); }
  void sequence_number(unsigned short n) { encode(6, 7, n); }

  friend std::istream& operator>>(std::istream& is, icmp_header& header) {
    return is.read(reinterpret_cast<char*>(header.rep_), 8);
  }

  friend std::ostream& operator<<(std::ostream& os, const icmp_header& header) {
    return os.write(reinterpret_cast<const char*>(header.rep_), 8);
  }


private:
  unsigned short decode(int a, int b) const {
    return (rep_[a] << 8) + rep_[b];
  }

  void encode(int a, int b, unsigned short n) {
    // 高8位放到较小的地址上
    rep_[a] = static_cast<byte_type>(n >> 8);
    // 低8位放到较大的地址上
    rep_[b] = static_cast<byte_type>(n & 0xFF);
  }

  byte_type rep_[8];
};


template<typename Iterator>
void compute_checksum(icmp_header& header, Iterator body_begin, Iterator body_end) {
  unsigned int sum = (header.type() << 8) + header.code()
    + header.identifier() + header.sequence_number();

  Iterator body_iter = body_begin;
  // 每次读取2个字节
  while (body_iter != body_end) {
    sum += (static_cast<byte_type>(*body_iter++) << 8);
    // 忽略奇数字节
    if (body_iter != body_end) {
      sum += static_cast<byte_type>(*body_iter++);
    }
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  header.checksum(static_cast<unsigned short>(~sum));
}


// Packet header for IPv4.
//
// The wire format of an IPv4 header is:
//
// 0               8               16                             31
// +-------+-------+---------------+------------------------------+      ---
// |       |       |               |                              |       ^
// |version|header |    type of    |    total length in bytes     |       |
// |  (4)  | length|    service    |                              |       |
// +-------+-------+---------------+-+-+-+------------------------+       |
// |                               | | | |                        |       |
// |        identification         |0|D|M|    fragment offset     |       |
// |                               | |F|F|                        |       |
// +---------------+---------------+-+-+-+------------------------+       |
// |               |               |                              |       |
// | time to live  |   protocol    |       header checksum        |   20 bytes
// |               |               |                              |       |
// +---------------+---------------+------------------------------+       |
// |                                                              |       |
// |                      source IPv4 address                     |       |
// |                                                              |       |
// +--------------------------------------------------------------+       |
// |                                                              |       |
// |                   destination IPv4 address                   |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---
// |                                                              |       ^
// |                                                              |       |
// /                        options (if any)                      /    0 - 40
// /                                                              /     bytes
// |                                                              |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---

class ipv4_header {
public:
  ipv4_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

  byte_type version() const { return (rep_[0] >> 4) & 0xF; }
  unsigned short header_length() const { return (rep_[0] & 0xF) * 4; }
  byte_type type_of_service() const { return rep_[1]; }
  unsigned short total_length() const { return decode(2, 3); }
  unsigned short identification() const { return decode(4, 5); }
  bool dont_fragment() const { return (rep_[6] & 0x40) != 0; }
  bool more_fragments() const { return (rep_[6] & 0x20) != 0; }
  unsigned short fragment_offset() const { return decode(6, 7) & 0x1FFF; }
  unsigned short time_to_live() const { return rep_[8]; }
  byte_type protocol() const { return rep_[9]; }
  unsigned short header_checksum() const { return decode(10, 11); }

  boost::asio::ip::address_v4 source_address() const {
    boost::asio::ip::address_v4::bytes_type bytes =
    { { rep_[12], rep_[13], rep_[14], rep_[15] } };
    return boost::asio::ip::address_v4(bytes);
  }

  boost::asio::ip::address_v4 destination_address() const {
    boost::asio::ip::address_v4::bytes_type bytes
      = { { rep_[16], rep_[17], rep_[18], rep_[19] } };
    return boost::asio::ip::address_v4(bytes);
  }

  friend std::istream& operator>>(std::istream& is, ipv4_header& header)
  {
    is.read(reinterpret_cast<char*>(header.rep_), 20); // 写入头部
    if (header.version() != 4)
      is.setstate(std::ios::failbit);
    std::streamsize options_length = header.header_length() - 20;
    if (options_length < 0 || options_length > 40)
      is.setstate(std::ios::failbit);
    else
      is.read(reinterpret_cast<char*>(header.rep_) + 20, options_length); // 写入选项
    return is;
  }

private:
  unsigned short decode(int a, int b) const {
    return (rep_[a] << 8) + rep_[b];
  }

  byte_type rep_[60];
};

}

#endif
