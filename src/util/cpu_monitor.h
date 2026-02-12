#pragma once

#include <atomic>
#include <mutex>
#include <set>
#include <thread>

namespace bpftrace::util {

// CPUMonitor watches for CPU hotplug events.
//
// It monitors CPU online/offline status to detect if any probe
// execution might be affected by hotplug events.
//
// Usage:
//   // In BPFtrace class:
//   std::unique_ptr<CPUMonitor> monitor_;
//
//   // In initialization:
//   monitor_ = std::make_unique<CPUMonitor>();
//   monitor_->register_cpu(cpu);
//   monitor_->start();
//
//   // On destruction:
//   // ~CPUMonitor() calls stop() and joins thread.
class CPUMonitor {
public:
  CPUMonitor();
  ~CPUMonitor();

  // Copy/Move disabled
  CPUMonitor(const CPUMonitor &) = delete;
  CPUMonitor &operator=(const CPUMonitor &) = delete;

  // Registers a CPU to be monitored. This is thread-safe.
  void register_cpu(int cpu);
  
  // Starts the monitoring thread.
  void start();
  
  // Stops the monitoring thread. Called by destructor.
  void stop();

private:
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
