#include <iostream>
#include <sodium.h>
#include <algorithm>
#include <vector>
#include <thread>
#include <fstream>
#include <chrono>
#include <array>
#include <cmath>
#include <condition_variable>
#include <mutex>
#include <cassert>
#include <numeric>

void escape(void* p) {
  asm volatile("" : : "g"(p) : "memory");
}

// F = void(buffin*, buffout*, buffin_size, buffout_size) F have to be thread-safe

template<typename F, size_t max_buff_size = 65536, size_t max_threads_count = 16>
class crypto_test {
public:
    crypto_test(F fun, std::string file_name);
    void test_buffer_size(std::function<void(unsigned char*, unsigned char*, size_t, size_t)>);
private:
    const F m_test_fun;
    std::ofstream m_file;
};

template<typename F, size_t max_buff_size, size_t max_threads_count>
crypto_test<F, max_buff_size, max_threads_count>::crypto_test(F fun, std::string file_name) : m_test_fun(fun), m_file(file_name)
{

}

template<typename F, size_t max_buff_size, size_t max_threads_count>
void crypto_test<F, max_buff_size, max_threads_count>::test_buffer_size(std::function<void(unsigned char*, unsigned char*, size_t, size_t)> init_buffer_lambda)
{
    std::array<size_t, max_threads_count> thread_results; //tests results from threads in ms
    std::array<std::thread, max_threads_count> threads;
	std::array<std::condition_variable, max_threads_count> thread_cv;
	std::array<bool, max_threads_count> thread_ready_flag;
	std::condition_variable trigger_cv; // if notifyed all threads starts
	std::mutex thread_mutex;
	bool threads_started = false; // protected by thread_mutex
    constexpr size_t iterations = 20000;

    auto thread_lambda = [&init_buffer_lambda, &thread_results, &iterations, this, &thread_cv, &thread_mutex, &threads_started, &trigger_cv, &thread_ready_flag]
	(size_t buff_size, size_t thread_index, size_t number_of_concurrent_threads) {
		assert(number_of_concurrent_threads > 0);
        std::vector<unsigned char> inbuff(buff_size);
        std::vector<unsigned char> outbuff(buff_size);
        init_buffer_lambda(inbuff.data(), outbuff.data(), buff_size, buff_size);

		std::unique_lock<std::mutex> lg(thread_mutex);
		thread_ready_flag.at(thread_index) = true;
		thread_cv.at(thread_index).notify_all(); // i am readry to work
		trigger_cv.wait(lg, [&threads_started]{return threads_started;}); // wait for start

        auto start_point = std::chrono::steady_clock::now();
        for (size_t j=0; j<iterations/number_of_concurrent_threads; j++)
        {
            m_test_fun(inbuff.data(), outbuff.data(), buff_size, max_buff_size);
        }
        auto end_point = std::chrono::steady_clock::now();
        thread_results.at(thread_index) = std::chrono::duration_cast<std::chrono::nanoseconds>(end_point - start_point).count();
    };


    for (size_t i=1; i < max_buff_size; i = std::ceil(i*1.5) ) // iterate through buffer size
    {
        for (size_t threads_count=0; threads_count<max_threads_count; threads_count++) // iterate through threads count
        {
            thread_results.fill(0);
			thread_ready_flag.fill(false); // all threads are not ready
            for (size_t j=0; j<=threads_count; j++) // iterate through threads count
            {
                threads.at(j) = std::move(std::thread(thread_lambda, i, j, threads_count+1));
            }

			for (size_t j=0; j<=threads_count; j++) { // waiting for all threads
				std::unique_lock<std::mutex> lg(thread_mutex);
				thread_cv.at(j).wait(lg, [&thread_ready_flag, &j]{return thread_ready_flag.at(j);});
			}

			{ // run all threads
				std::unique_lock<std::mutex> lg(thread_mutex);
				threads_started = true;
			}
			auto start_point = std::chrono::steady_clock::now();
			trigger_cv.notify_all();


            for (size_t j=0; j<=threads_count; j++) // iterate through threads count
            {
                threads.at(j).join();
            }
			auto stop_point = std::chrono::steady_clock::now();
			threads_started = false;

            size_t time_ms = std::chrono::duration_cast<std::chrono::nanoseconds>(stop_point - start_point).count();
            // buff_size threads_count time_ms
            m_file << i << '\t' << threads_count << '\t' << time_ms/static_cast<double>(iterations) << '\n';

//            m_file << i << '\t' << threads_count+1 << '\t' << (time_ms/static_cast<double>(iterations))/((threads_count+1)*(threads_count+1))<< '\n'; // buff_size threads_count time_ms
            // threads_count+1 becouse array index starts from 0

        }
    }
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Can not init sodium." << std::endl;
            return 1;
    }

    // poly auth
    unsigned char key[crypto_onetimeauth_KEYBYTES];
    std::fill_n(key, crypto_onetimeauth_KEYBYTES, 0xfd);
//     crypto_onetimeauth_keygen(key); // was introduced in libsodium 1.0.12.
    auto poly = [&key](unsigned char* buff_in, unsigned char* buff_out, size_t in_size, size_t out_size ){
		escape(buff_out);
        crypto_onetimeauth(buff_out, buff_in, in_size, key);
		escape(buff_out);
    };
    {
        crypto_test<decltype(poly)> crypt(poly, "poly_auth_results.txt");
        crypt.test_buffer_size([](unsigned char* buff, unsigned char*, size_t size, size_t){std::fill_n(buff, size, 0xfd);});
    }

    // poly verify
    auto poly_verify = [&key](unsigned char* buff_in, unsigned char* buff_out, size_t in_size, size_t out_size ){
		escape(buff_out);
        if (crypto_onetimeauth_verify(buff_out, buff_in, in_size, key) != 0) {
           std::cerr << "Poly verification fail" << std::endl;
           std::abort();
        }
		escape(buff_out);
    };
    auto init_buffers = [&poly, &key](unsigned char* buff_in, unsigned char* buff_out, size_t in_size, size_t out_size ){
        std::fill_n(buff_in, in_size, 0xfd);
        poly(buff_in, buff_out, in_size, out_size);
    };
    {
        crypto_test<decltype(poly_verify)> crypt(poly_verify, "poly_verify_results.txt");
        crypt.test_buffer_size(init_buffers);
    }



    return 0;
}
