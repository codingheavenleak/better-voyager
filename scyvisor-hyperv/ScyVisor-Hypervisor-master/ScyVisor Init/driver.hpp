#ifndef DRIVER_HPP
#define DRIVER_HPP
#define device_name "\\\\.\\{StorSync01}"
#include <winternl.h> 
#include <cstdint>


struct dtb_buffer {
	uint64_t dtb;
	bool valid;
};

static dtb_buffer dtb_buffers[2];
static int current_buffer = 0;
static std::mutex dtb_mutex;

namespace module
{
	static uint32_t process_id;
	static uintptr_t image_base;
}

extern "C" __int64 direct_device_control(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	uint32_t IoControlCode,
	PVOID InputBuffer,
	uint32_t InputBufferLength,
	PVOID OutputBuffer,
	uint32_t OutputBufferLength);

namespace driver
{



	using requests = enum _requests
	{
		invoke_unique,
		invoke_start,
		invoke_base,
		invoke_context,
		invoke_read,
		invoke_write,
		invoke_mouse,
		invoke_init,
		invoke_allocate,
		invoke_protect,
		invoke_free,
		invoke_swap,
		invoke_query,
		invoke_scan,
		invoke_translate,
		invoke_dtb
	};
	using prequests = requests*;

	using base_invoke = struct _base_invoke {
		uint32_t pid;
		uintptr_t handle;
		const char* name;
		size_t size;
	};
	using pbase_invoke = base_invoke*;

	using context_invoke = struct _context_invoke {
		uint32_t pid;
		HANDLE context;
	};
	using pcontext_invoke = context_invoke*;

	typedef struct _read_invoke {
		uint32_t pid;
		uintptr_t address;
		uintptr_t dtb;
		void* buffer;
		size_t size;
	} read_invoke, * pread_invoke;

	using write_invoke = struct _write_invoke {
		uint32_t pid;
		uintptr_t address;
		uintptr_t dtb;
		void* buffer;
		size_t size;
	};
	using pwrite_invoke = write_invoke*;

	using init_invoke = struct _init_invoke {
		int count = 0;
	};
	using last_message = init_invoke*;

	using mouse_invoke = struct _mouse_invoke {
		uint32_t pid;
		USHORT IndicatorFlags;
		LONG MovementX;
		LONG MovementY;
		ULONG PacketsConsumed;
	};
	using pmouse_invoke = mouse_invoke*;

	using allocate_invoke = struct _allocate_invoke {
		uintptr_t address;
		uint32_t pid;
		size_t size;
		DWORD protection;
		int type;
	};
	using pallocate_invoke = allocate_invoke*;

	using protect_invoke = struct _protect_invoke {
		uint32_t pid;
		uintptr_t address;
		size_t size;
		DWORD protection;
		DWORD old_protection;
	};
	using pprotect_invoke = protect_invoke*;

	using free_invoke = struct _free_invoke {
		uintptr_t address;
		uint32_t pid;
		size_t size;
		ULONG type;
	};
	using pfree_invoke = free_invoke*;

	using swap_invoke = struct _swap_invoke {
		uint32_t pid;
		uintptr_t address;
		uintptr_t address2;
		uintptr_t og_pointer;
	};
	using pswap_invoke = swap_invoke*;

	using query_invoke = struct _query_invoke {
		uint32_t pid;
		uintptr_t address;
		uintptr_t address_2;
		ULONG protect;
		size_t mem_size;
	};
	using pquery_invoke = query_invoke*;

	using scan_invoke = struct _scan_invoke {
		uint32_t pid;
		uintptr_t module_base;
		uintptr_t address;
		SIZE_T size;
		const char* signature;
	};
	using pscan_invoke = scan_invoke*;

	using translate_invoke = struct _translate_invoke {
		uintptr_t virtual_address;
		uintptr_t directory_base;
		void* physical_address;
	};
	using ptranslate_invoke = translate_invoke*;

	using dtb_invoke = struct _dtb_invoke {
		uint32_t pid;
		uintptr_t dtb;
		ULONGLONG operation;
	};
	using pdtb_invoke = dtb_invoke*;

	using invoke_data = struct _invoke_data
	{
		uint32_t unique;
		requests code;
		void* data;
	};
	using pinvoke_data = invoke_data*;

	static int32_t m_pid = 0;
	static void* m_handle = nullptr;

	static uintptr_t image_base = 0;
	inline uintptr_t directory_base;




	/*INITIALIZE*/

	[[nodiscard]] const bool initialize_handle();
	[[nodiscard]] const bool device_io_control(void* data, requests code);
	[[nodiscard]] const bool update(int a_pid);
	[[nodiscard]] const bool initialize(uintptr_t image);
	[[nodiscard]] const uintptr_t get_dtb(uint32_t pid);
	[[nodiscard]] const uintptr_t translate_address(uintptr_t virtual_address, uintptr_t directory_base);
	[[nodiscard]] const uintptr_t get_image_base(const char* module_name);
	[[nodiscard]] const uintptr_t get_process_context();

	/*INJECT MOUSE*/
	[[nodiscard]] const int initaite_mouse_context();
	[[nodiscard]] const int inject_mouse(LONG MovementX, LONG MovementY);

	/*MEMORY*/
	[[nodiscard]] const uintptr_t allocate_virtual(const size_t size, const int type, const DWORD protection);
	[[nodiscard]] const uintptr_t swap_virtual(const uintptr_t address, const uintptr_t address2);
	[[nodiscard]] const DWORD protect_virtual(const uintptr_t address, const size_t size, const DWORD protection);
	[[noreturn]] void free_virtual(const uintptr_t address, const size_t size, const ULONG type);
	[[noreturn]] void query_virtual(const uintptr_t address);

	/*RWX*/
	[[nodiscard]] const bool read_physical(const uintptr_t address, void* buffer, const size_t size);
	[[nodiscard]] const bool write_physical(const uintptr_t address, void* buffer, const size_t size);
	[[nodiscard]] const bool signature_scan(const char* signature, const size_t size);
	[[nodiscard]] const bool IsValid(const uint64_t address);

	[[nodiscard]] const std::uint32_t get_process_id(const std::wstring& proc_name);

	template <typename type>
	[[nodiscard]] bool write(const uintptr_t address, type value)
	{
		return write_physical(address, &value, sizeof(type));
	}



	template <typename T>
	[[nodiscard]] inline T read(const uintptr_t address) noexcept
	{
		T result;
		read_physical(address, &result, sizeof(T));
		return result;
	}


	template <typename t>
	[[nodiscard]] bool read_array(const uintptr_t address, t buffer, size_t size)
	{
		return read_physical(address, buffer, size);
	}


}
#endif // ! DRIVER_HPP