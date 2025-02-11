#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <thread>

std::mutex print_mutex;

// Overriding global operator new
void* operator new(std::size_t size) 
{
    void* ptr = std::malloc(size);
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << std::hex << "         new: TID " << std::this_thread::get_id() << " PTR " << ptr << " BYTES 0x" << size << "\n";
    }
    return ptr;
}

// Overriding global operator delete
void operator delete(void* ptr) noexcept 
{
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << std::hex << "      delete: TID " << std::this_thread::get_id() << " PTR " << ptr << "\n";
    }
    std::free(ptr);
}

namespace statistics::memory
{
    struct allocation
    {
        std::size_t size = 0;
        std::size_t count = 0;
        bool allocated = false;
    };

    struct alocation_statistics
    {
        std::size_t current = 0;
        std::size_t peak = 0;
        std::mutex mutex;
        std::map<std::uintptr_t, allocation> allocation_map;
    };

    std::map<std::thread::id, alocation_statistics> allocations;
    std::mutex allocations_mutex;

    thread_local alocation_statistics* thread_allocation_statistics = nullptr;

    void TrackAllocation(std::thread::id thread_id, std::uintptr_t ptr, std::size_t bytes, std::size_t count)
    {
        if (!thread_allocation_statistics)
        {
            std::lock_guard<std::mutex> lock(allocations_mutex);
            auto& as = allocations[thread_id];
            thread_allocation_statistics = &as;
        }

        std::lock_guard<std::mutex> lock(thread_allocation_statistics->mutex);

        thread_allocation_statistics->current += bytes * count;
        thread_allocation_statistics->peak = thread_allocation_statistics->peak > thread_allocation_statistics->current ? 
                thread_allocation_statistics->peak : thread_allocation_statistics->current;

        auto& alloc = thread_allocation_statistics->allocation_map[ptr];
        alloc.allocated = true;
        alloc.size = bytes;
        alloc.count = count;

        {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << std::hex << "  allocation: TID " << thread_id << " PTR 0x" << ptr << " SIZE 0x" << bytes << " CNT 0x" << count << "\n";
        }
    }

    void TrackDeallocation(std::thread::id thread_id, std::uintptr_t ptr, std::size_t bytes, std::size_t count)
    {
        if (!thread_allocation_statistics)
        {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << std::hex << "deallocation: TID " << thread_id << " PTR 0x" << ptr << " SIZE 0x" << bytes << " CNT 0x" << count << " orphaned\n";
            return;
        }
        
        std::lock_guard<std::mutex> lock(thread_allocation_statistics->mutex);

        thread_allocation_statistics->current -= bytes * count;

        auto& alloc = thread_allocation_statistics->allocation_map[ptr];
        alloc.allocated = false;
        if (alloc.size != bytes || alloc.count != count)
        {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << std::hex << "deallocation: TID 0x" << thread_id << " PTR 0x" << ptr << " SIZE 0x" << bytes << " CNT 0x" << count <<  ", mismatch!, allocated SIZE 0x" << alloc.size << " CNT 0x" << alloc.count <<  "\n";
        }

        {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << std::hex << "deallocation: TID 0x" << thread_id << " PTR 0x" << ptr << " SIZE 0x" << bytes << " CNT 0x" << count << "\n";
        }
    }

    void PrintStatistics()
    {
        for (auto& [thread_id, allocation_statistics] : allocations)
        {
            std::lock_guard<std::mutex> lock(allocation_statistics.mutex);

            std::cout << std::hex << "------------- TID 0x" << thread_id << "-------------\n";
            for (const auto& [ptr, allocation] : allocation_statistics.allocation_map)
            {
                std::cout << std::hex << " PTR 0x" << ptr << " SIZE 0x" << allocation.size << " CNT 0x" << allocation.count <<  (allocation.allocated ? " allocated " : " deallocated ")  <<  "\n";
            }
            std::cout << std::hex << " peek 0x" << allocation_statistics.peak << "\n current 0x" << allocation_statistics.current <<  "\n";
            std::cout << "\n";
        }
    }
} // namespace statistics::memory


namespace e{

template <typename T>
class allocator {
public:
    using value_type = T;

    allocator() = default;

    template <typename U>
    allocator(const allocator<U>&) {}

    T* allocate(std::size_t n) {
        auto ptr = std::allocator<T>().allocate(n);
        statistics::memory::TrackAllocation(std::this_thread::get_id(), reinterpret_cast<std::uintptr_t>(ptr), sizeof(T), n);
        return ptr;
    }

    void deallocate(T* p, std::size_t n) {
        statistics::memory::TrackDeallocation(std::this_thread::get_id(), reinterpret_cast<std::uintptr_t>(p), sizeof(T), n);
        std::allocator<T>().deallocate(p, n);
    }
};

using string = std::basic_string<char, std::char_traits<char>, allocator<char>>;
using wstring = std::basic_string<wchar_t, std::char_traits<wchar_t>, allocator<wchar_t>>;

template<typename T>
using vector = std::vector<T, allocator<T>>;

template<typename K, typename V>
using map = std::map<K, V, std::less<K>, allocator<std::pair<K, V>>>;

template<typename T>
using unique_ptr = std::unique_ptr<T>;

template<typename T>
using shared_ptr = std::shared_ptr<T>;

template<typename T, typename... Args>
std::shared_ptr<T> make_shared(Args&&... args) 
{
    if (std::is_trivial_v<T>)
    {
        return std::allocate_shared<T>(allocator<T>(), std::forward<Args>(args)...); 
    }
    else
    {
        using TV= typename T::value_type;
        return std::allocate_shared<T>(allocator<TV>(), std::forward<Args>(args)...); 
    }
}

} //  namespace e

int main()
{
    {
        std::cout << "\nHello world!" << "\n";
        e::vector<e::string> vec;
        vec.emplace_back(10, 'a');
        vec.emplace_back(10, 'z');
        vec[0].append(50, '.');
        vec[0].append(std::string(" standard string"));
        
        // won't commpile, can't copy the string
        //vec.push_back(std::string("standard string"));

        vec.emplace_back(std::string("standard string"));
    }

    {
        std::cout << "\nHello world!" << "\n";
        std::shared_ptr<std::string> sptr = std::allocate_shared<std::string>(std::allocator<std::string::value_type>(), 10, 'x');
        e::shared_ptr<e::string> sptr1 = std::allocate_shared<e::string>(e::allocator<e::string::value_type>(), 10, 'y');
        e::shared_ptr<e::string> sptr2 = e::make_shared<e::string>(10, 'z');
        std::cout << *sptr << "\n";
        std::cout << *sptr1 << "\n";
        std::cout << *sptr2 << "\n";
    }

    {
        std::cout << "\nHello world!" << "\n";
        e::vector<int> vec2;
        vec2.push_back(10);
        vec2.push_back(20);
        vec2.push_back(30);
        vec2.push_back(40);
        vec2.push_back(50);
    }

    std::cout << "========================\n";

    const int num_threads = 5;
    std::thread threads[num_threads];

    for (int i = 0; i < num_threads; ++i) {
        threads[i] = std::thread([](){
            e::vector<e::string> vec;
            vec.emplace_back(10, 'a');
            vec.emplace_back(10, 'z');
        });
    }

    for (int i = 0; i < num_threads; ++i) {
        threads[i].join();
    }

    std::cout << "========================\n";

    statistics::memory::PrintStatistics();
    return 0;
}