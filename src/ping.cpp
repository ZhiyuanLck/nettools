#include <iostream>
#include <iomanip>
#include <float.h>
#include <string>
#include <boost/system.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <algorithm>

#include "header.hpp"

namespace asio = boost::asio;
using boost::system::error_code;

namespace nettool {

namespace posix_time = boost::posix_time;
using asio::ip::icmp;
using asio::deadline_timer;


// 1. Resolve destination address with DNS resolver
// 2. Construct and send ICMP message
//    -> wait for timeout or signal for a valid return message
//    -> sent the next message
// 3. Prepare buffer -> handle received messages -> receive next
class pinger {
public:
  pinger(asio::io_service& io_service, const char* destination)
      : resolver_(io_service),
      socket_(io_service, icmp::v4()),
      timer_(io_service),
      sequence_number_(0),
      num_replies_(0),
      signals_(io_service, SIGINT),
      time_init_(posix_time::microsec_clock::universal_time()),
      num_transmitted_(0), num_received_(0),
      ttl_min_(LDBL_MAX), ttl_max_(0),
      ttl_sum_(0), ttl_sum2_(0)
  {
    signals_.async_wait(boost::bind(&pinger::handle_termination,
          this, asio::placeholders::error, asio::placeholders::signal_number));
    // basic_resolver: protocol, services, flags
    icmp::resolver::query query(icmp::v4(), destination, "");
    // a iterator of queried endpoint is returned
    destination_ = *resolver_.resolve(query);

    start_send();
    start_receive();
  }
private:
  void handle_termination(const error_code& ec, int n) {
    auto now = posix_time::microsec_clock::universal_time();
    long double total_time = (now - time_init_).total_milliseconds() / 1000.0;
    ttl_sum_ /= num_received_;
    ttl_sum2_ /= num_received_;
    long double ttl_mdev = sqrtl(ttl_sum2_ - ttl_sum_ * ttl_sum_);
    std::cout << std::endl
      << num_transmitted_ << " packets transmitted, "
      << num_received_ << " received, "
      << num_transmitted_ - num_received_ << " lossed, "
      << std::fixed << std::setprecision(2)
      << (num_transmitted_ - num_received_) / static_cast<long double>(num_transmitted_)
      << "\% loss, time "
      << std::setprecision(3) << total_time << " s\n"
      << "rtt min/avg/max/mdev "
      << ttl_min_ << "/"
      << ttl_sum_ << "/"
      << ttl_max_ << "/"
      << ttl_mdev << " ms\n";
    exit(0);
  }

  // Consider the time to send the message
  // 1. First send, every thing is ok
  // 2. Send after 5s's timeout call, and if the valid return message is
  // arrived almost simultaneously or later.
  //   1) If the sequence number has increased, so the message is
  //   invalid
  //   2) If the sequence number has not increased, we need to check
  //   whether the received message is timeout:
  //     i) If the send time is not reset, the message must be timeout,
  //     then is invalid.
  //     ii) If the send time is reset, the message may be deemed to have
  //     arrived in time, but the sequence number has increased, so the message
  //     is invalid too.
  // 3. Send after a valid return message: since we have not sent the next
  // message, there should be no valid return message to be received
  void start_send() {
    std::string body(56, 'z');

    // Construct header
    // The protocol of ip::icmp is IPPROTO_ICMP, so the kernel will
    // automatically add the correct ip header
    icmp_header echo_request;
    echo_request.type(icmp_header::echo_request);
    echo_request.code(0); // for echo request/reply
    echo_request.identifier(get_identifier());
    echo_request.sequence_number(++sequence_number_);
    compute_checksum(echo_request, body.begin(), body.end());
    ++num_transmitted_;

    // Encode
    asio::streambuf request_buffer;
    std::ostream os(&request_buffer);
    os << echo_request << body;

    // Send request
    time_sent_ = posix_time::microsec_clock::universal_time();
    socket_.send_to(request_buffer.data(), destination_);

    // Set a timer of 5s, whose handle may be called when a valid message is
    // detected.
    num_replies_ = 0;
    timer_.expires_at(time_sent_ + posix_time::seconds(5));
    timer_.async_wait(boost::bind(&pinger::handle_timeout, this, asio::placeholders::error));
  }

  void handle_timeout(const error_code& ec) {
    if (num_replies_ == 0 && !ec)
      std::cout << "Request timed out" << std::endl;
    if (ec && ec.value() != boost::system::errc::operation_canceled)
      std::cerr << ec.message() << std::endl;

    // Send the next request after at least 1s
    timer_.expires_at(time_sent_ + posix_time::seconds(1));
    timer_.async_wait(boost::bind(&pinger::start_send, this));
  }

  void start_receive() {
    // Discard possible data
    reply_buffer_.consume(reply_buffer_.size());
    // Prepare the buffer for at most 64KB data
    socket_.async_receive(reply_buffer_.prepare(65536),
        boost::bind(&pinger::handle_receive, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
  }

  void handle_receive(const error_code& ec, std::size_t length) {
    if (ec)
      std::cerr << ec.message() << std::endl;
    else {
      reply_buffer_.commit(length);

      // Discard timeout return message
      posix_time::ptime tmp = posix_time::microsec_clock::universal_time();
      if ((tmp - time_sent_).total_milliseconds() > 5000) return;

      // Decode
      std::istream is(&reply_buffer_);
      ipv4_header ipv4_hdr;
      icmp_header icmp_hdr;
      is >> ipv4_hdr >> icmp_hdr;

      // Filter the message we are interested
      if (is && icmp_hdr.type() == icmp_header::echo_reply
          && icmp_hdr.identifier() == get_identifier()
          && icmp_hdr.sequence_number() == sequence_number_) {
        // Call handle_timeout only when the first valid message arrive
        if (num_replies_++ == 0)
          timer_.cancel();

        posix_time::ptime now = posix_time::microsec_clock::universal_time();
        ++num_received_;
        long double ttl = (now - time_sent_).total_microseconds() / 1000.0;
        ttl_min_ = fmin(ttl_min_, ttl);
        ttl_max_ = fmax(ttl_max_, ttl);
        ttl_sum_ += ttl;
        ttl_sum2_ += ttl * ttl;
        std::cout << length - ipv4_hdr.header_length()
          << " bytes from " << ipv4_hdr.source_address()
          << ": icmp_seq=" << icmp_hdr.sequence_number()
          << ", ttl=" << ipv4_hdr.time_to_live()
          << ", time=" << std::fixed << std::setprecision(3)
          << ttl << " ms"
          << std::endl;
      }
    }
    start_receive();
  }

  static unsigned short get_identifier() {
    return static_cast<unsigned short>(::getpid());
  }

  icmp::resolver resolver_;
  icmp::endpoint destination_;
  icmp::socket socket_; // raw socket
  deadline_timer timer_;
  unsigned short sequence_number_;
  posix_time::ptime time_sent_;
  asio::streambuf reply_buffer_;
  std::size_t num_replies_;

  asio::signal_set signals_;
  posix_time::ptime time_init_;
  std::size_t num_transmitted_;
  std::size_t num_received_;
  long double ttl_min_;
  long double ttl_max_;
  long double ttl_sum_;
  long double ttl_sum2_;
};

}

int main(int argc, char* argv[]) {
  try {
    if (argc != 2) {
      std::cerr << "Usage: ping <host>" << std::endl;
      return 1;
    }

    error_code ec;
    asio::io_service io_service;
    nettool::pinger p(io_service, argv[1]);
    io_service.run(ec);
  } catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
  }
}
