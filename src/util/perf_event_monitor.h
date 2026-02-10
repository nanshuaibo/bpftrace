#pragma once

#include <atomic>
#include <mutex>
#include <set>
#include <thread>

namespace bpftrace::util {

// PerfEventMonitor watches for CPU hotplug events using Netlink uevents.
//
// It establishes a NETLINK_KOBJECT_UEVENT socket to listen for kernel
// messages about CPU online/offline status.
//
// Usage:
//   auto &monitor = PerfEventMonitor::instance();
//   monitor.register_cpu(cpu);
//   monitor.start();
//   ...
//   monitor.stop();
class PerfEventMonitor {
public:
  static PerfEventMonitor &instance();

  PerfEventMonitor(const PerfEventMonitor &) = delete;
  PerfEventMonitor &operator=(const PerfEventMonitor &) = delete;

  void register_cpu(int cpu);
  void start();
  void stop();
  void reset();

private:
  PerfEventMonitor();
  ~PerfEventMonitor();

  void monitor_loop();
  void handle_uevent(const char *buffer, ssize_t len);

  std::thread monitor_thread_;
  std::atomic<bool> running_{ false };
  std::mutex mutex_;
  std::set<int> monitored_cpus_;
  std::set<int> alerted_cpus_;

  int netlink_fd_ = -1;
  int event_fd_ = -1; // For waking up poll()
};

} // namespace bpftrace::util
