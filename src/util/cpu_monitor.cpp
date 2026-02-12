#include "util/cpu_monitor.h"
#include "log.h"
#include <cstring>
#include <linux/netlink.h>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace bpftrace::util {

CPUMonitor::CPUMonitor()
{
  event_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (event_fd_ < 0) {
    LOG(ERROR) << "Failed to create eventfd for CPUMonitor: " << strerror(errno);
  }

}

CPUMonitor::~CPUMonitor()
{
  stop();
  if (event_fd_ >= 0)
    close(event_fd_);
}

void CPUMonitor::register_cpu(int cpu)
{
  std::lock_guard<std::mutex> lock(mutex_);
  monitored_cpus_.insert(cpu);
}

void CPUMonitor::start()
{
  bool expected = false;
  if (!running_.compare_exchange_strong(expected, true))
    return;
    

  
  // Set up Netlink socket
  netlink_fd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
  if (netlink_fd_ < 0) {
    LOG(WARNING) << "Failed to create Netlink socket for CPU hotplug monitoring: "
                 << strerror(errno);
  } else {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = 1; // Listen to kernel multicast group 1

    if (bind(netlink_fd_, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
      LOG(WARNING) << "Failed to bind Netlink socket: " << strerror(errno);
      close(netlink_fd_);
      netlink_fd_ = -1;
    }
  }

  monitor_thread_ = std::thread(&CPUMonitor::monitor_loop, this);
}

void CPUMonitor::stop()
{
  if (!running_.exchange(false))
    return;

  // Wake up poll()
  uint64_t val = 1;
  if (event_fd_ >= 0) {
    if (write(event_fd_, &val, sizeof(val)) < 0) {
      // Best effort notification
    }
  }

  if (monitor_thread_.joinable())
    monitor_thread_.join();

  if (netlink_fd_ >= 0) {
    close(netlink_fd_);
    netlink_fd_ = -1;
  }
}

void CPUMonitor::monitor_loop()
{
  if (netlink_fd_ < 0) return;

  struct pollfd fds[2];
  fds[0].fd = netlink_fd_;
  fds[0].events = POLLIN;
  fds[1].fd = event_fd_;
  fds[1].events = POLLIN;

  char buffer[4096];

  while (running_) {


    int ret = poll(fds, 2, -1); // Infinite timeout, wait for event
    if (ret < 0) break;

    if (fds[1].revents & POLLIN) {
      // Stopped via eventfd
      uint64_t val;
      if (read(event_fd_, &val, sizeof(val)) < 0) {
        // Ignore errors, we're stopping anyway
      }
      break;
    }

    if (fds[0].revents & POLLIN) {
      ssize_t len = recv(netlink_fd_, buffer, sizeof(buffer), 0);
      if (len > 0) {
        handle_uevent(buffer, len);
      }
    }
  }
}

void CPUMonitor::handle_uevent(const char *buffer, ssize_t len)
{
  // Netlink messages are a series of null-terminated strings
  
  std::string action, subsystem, devpath;
  const char *ptr = buffer;
  const char *end = buffer + len;

  while (ptr < end) {
    std::string s(ptr);
    if (s.find("ACTION=") == 0) action = s.substr(7);
    else if (s.find("SUBSYSTEM=") == 0) subsystem = s.substr(10);
    else if (s.find("DEVPATH=") == 0) devpath = s.substr(8);
    
    ptr += s.length() + 1;
  }

  // Filter for CPU offline events
  if (subsystem == "cpu" && action == "offline") {
    size_t pos = devpath.rfind("/cpu");
    if (pos != std::string::npos && pos + 4 < devpath.length()) {
      try {
        int cpu = std::stoi(devpath.substr(pos + 4));
        
        std::lock_guard<std::mutex> lock(mutex_);
        if (monitored_cpus_.count(cpu) && alerted_cpus_.find(cpu) == alerted_cpus_.end()) {
           LOG(WARNING) << "CPU " << cpu << " went offline during probe execution. "
                        << "Data from this CPU may be incomplete.";
           alerted_cpus_.insert(cpu);
        }
      } catch (...) {}
    }
  }
}

} // namespace bpftrace::util
