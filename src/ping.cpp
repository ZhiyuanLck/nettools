#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/asio/steady_timer.hpp>
#include <algorithm>
// #include <fmt/core.h>
// #include <chrono>

#include "header.hpp"

namespace asio = boost::asio;

namespace nettool {

namespace posix_time = boost::posix_time;
using asio::ip::icmp;
using asio::deadline_timer;

class pinger {
public:
  pinger(asio::io_service& io_service, const char* destination)
      : resolver_(io_service), socket_(io_service, icmp::v4()),
      timer_(io_service), sequence_number_(0), num_replies_(0) {
    // protocol, services(port num), resolve_flags
    icmp::resolver::query query(icmp::v4(), destination, "");
    // resolve查询返回一个迭代器，代表查询到的ip端点
    destination_ = *resolver_.resolve(query);

    start_send();
    start_receive();
  }
private:
  void start_send() {
    std::string body("Some message.");

    // Init header
    icmp_header echo_request;
    echo_request.type(icmp_header::echo_request);
    echo_request.code(0); // 回显应答
    echo_request.identifier(get_identifier());
    echo_request.sequence_number(++sequence_number_);
    compute_checksum(echo_request, body.begin(), body.end()); // 计算校验和

    // Encode
    asio::streambuf request_buffer;
    std::ostream os(&request_buffer);
    os << echo_request << body;

    // Send request
    time_sent_ = posix_time::microsec_clock::universal_time();
    socket_.send_to(request_buffer.data(), destination_);

    // 等待回复5s
    num_replies_ = 0;
    timer_.expires_at(time_sent_ + posix_time::seconds(5));
    timer_.async_wait(boost::bind(&pinger::handle_timeout, this));
  }

  void handle_timeout() {
    if (num_replies_ == 0)
      std::cout << "Request timed out" << std::endl;

    // 1s后再发送
    timer_.expires_at(time_sent_ + posix_time::seconds(1));
    timer_.async_wait(boost::bind(&pinger::start_send, this));
  }

  void start_receive() {
    // 丢弃已有的数据
    reply_buffer_.consume(reply_buffer_.size());
    // 准备接收最多64KB的数据
    socket_.async_receive(reply_buffer_.prepare(65536),
        boost::bind(&pinger::handle_receive, this, asio::placeholders::bytes_transferred));
  }

  void handle_receive(std::size_t length) {
    reply_buffer_.commit(length);

    // Decode
    std::istream is(&reply_buffer_);
    ipv4_header ipv4_hdr;
    icmp_header icmp_hdr;
    is >> ipv4_hdr >> icmp_hdr;

    // 过滤，只需要回显消息以及表示符匹配的消息
    if (is && icmp_hdr.type() == icmp_header::echo_reply
        && icmp_hdr.identifier() == get_identifier()
        && icmp_hdr.sequence_number() == sequence_number_) {
      // 收到第一个回复时中断5s的定时器
      if (num_replies_++ == 0)
        timer_.cancel();
      posix_time::ptime now = posix_time::microsec_clock::universal_time();
      std::cout << length - ipv4_hdr.header_length()
        << " bytes from " << ipv4_hdr.source_address()
        << ": icmp_seq=" << icmp_hdr.sequence_number()
        << ", ttl=" << ipv4_hdr.time_to_live()
        << ", time=" << (now - time_sent_).total_milliseconds() << " ms"
        << std::endl;
      // fmt::print("{0} bytes from {1}: icmp_seq = {2}, ttl = {3}, time = {4} ms",
          // length - ipv4_hdr.header_length(),
          // ipv4_hdr.source_address(),
          // icmp_hdr.sequence_number(),
          // ipv4_hdr.time_to_live(),
          // (now - time_sent_).total_milliseconds());

      start_receive();
    }
  }

  static unsigned short get_identifier() {
    return static_cast<unsigned short>(::getpid());
  }

  icmp::resolver resolver_; // DNS解析
  icmp::endpoint destination_; // 目标套接字端点
  icmp::socket socket_; // stream_socket
  deadline_timer timer_; // 定时器
  unsigned short sequence_number_;
  posix_time::ptime time_sent_;
  asio::streambuf reply_buffer_;
  std::size_t num_replies_;
};

}

int main(int argc, char* argv[]) {
  try {
    if (argc != 2) {
      std::cerr << "Usage: ping <host>" << std::endl;
      return 1;
    }

    asio::io_service io_service;
    nettool::pinger p(io_service, argv[1]);
    io_service.run();
  } catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
  }
}
