#ifndef BLOCKING_QUEUE_H
#define BLOCKING_QUEUE_H

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>

// A bounded queue for handing work between threads. Push blocks while the queue is
// full; Pop blocks while it is empty and returns false once it is closed and drained.
template <typename T>
class BlockingQueue {
public:
    explicit BlockingQueue(std::size_t capacity) : capacity_(capacity ? capacity : 1) {}

    void Push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return items_.size() < capacity_ || closed_; });
        items_.push_back(std::move(item));
        lock.unlock();
        not_empty_.notify_one();
    }

    bool Pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] { return !items_.empty() || closed_; });
        if (items_.empty()) {
            return false;
        }
        item = std::move(items_.front());
        items_.pop_front();
        lock.unlock();
        not_full_.notify_one();
        return true;
    }

    // No more items will be pushed; wakes up every waiting consumer.
    void Close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::deque<T> items_;
    std::size_t capacity_;
    bool closed_ = false;
};

#endif // BLOCKING_QUEUE_H
