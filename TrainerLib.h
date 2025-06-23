#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <set>
#include <list>
#include <algorithm>
#include <functional>
#include <map>
#include <mutex>
#include <Windows.h>

#undef GetObject

namespace TrainerLib
{
	enum class LogLevel : uint8_t
	{
		Debug = 0,
		Info = 1,
		Warning = 2,
		Error = 3,
	};

	/* Log messages. */
	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class ILogger
	{
	public:
		virtual bool IsConnected() = 0;
		virtual void Log(LogLevel level, const wchar_t* message) = 0;
	};

	static const char* const ILogger_Version = "ILogger_001";

	/* Get data passed to the trainer at startup. */
	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class ITrainerArgs
	{
	public:
		virtual const char* GetFlags() = 0;
	};

	static const char* const ITrainerArgs_Version = "ITrainerArgs_001";

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IValueChangedHandler
	{
	public:
		virtual void HandleValueChanged(const char* name, double value) = 0;
	};

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IRemoteClient
	{
	public:
		virtual double GetValue(const char* name) = 0;
		virtual void SetValue(const char* name, double value) = 0;
		virtual void AddValueChangedHandler(IValueChangedHandler* handler) = 0;
		virtual void RemoveValueChangedHandler(IValueChangedHandler* handler) = 0;
	};

	static const char* const IRemoteClient_Version = "IRemoteClient_001";

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IProcess
	{
	public:
		virtual void* GetModuleBaseAddress(const wchar_t* module = nullptr) = 0;
		virtual uint32_t GetModuleTimestamp(const wchar_t* module = nullptr) = 0;
		virtual void* ScanProcess(const char* terms, void* startAddress = nullptr, void* endAddress = nullptr) = 0;
		virtual void* ScanModule(const char* terms, const wchar_t* module = nullptr, void* startAddress = nullptr) = 0;
		virtual wchar_t* GetMainModuleBaseName() = 0;
	};

	static const char* const IProcess_Version = "IProcess_001";

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class ITask
	{
	public:
		virtual void Kill() = 0;
		virtual void End() = 0;
		virtual bool ShouldEnd() = 0;
		virtual bool HasEnded() = 0;
		virtual uint32_t ThreadId() = 0;
	};

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class ITaskRoutine
	{
	public:
		virtual void Execute(ITask* task) = 0;
	};

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class ITaskManager
	{
	public:
		virtual ITask* CreateTask(ITaskRoutine* routine) = 0;
		virtual void EndAllTasks() = 0;
		virtual void TerminateAllTasks() = 0;
	};

	static const char* const ITaskManager_Version = "ITaskManager_001";

	enum class BreakpointTrigger : uint8_t
	{
		Execute = 0,
		Write = 1,
		ReadWrite = 2,
		Opcode = 3,
		Dereference = 4,
	};

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IBreakpointHandler
	{
	public:
		virtual bool HandleBreakpoint(void* address, uint32_t threadId, PCONTEXT context, bool post) = 0;
	};

	/* Allows setting software (INT3) and hardware breakpoints. */
	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IDebugger
	{
	public:
		virtual void AddBreakpointHandler(IBreakpointHandler* handler);
		virtual void RemoveBreakpointHandler(IBreakpointHandler* handler);
		virtual bool SetBreakpoint(void* address, BreakpointTrigger trigger = BreakpointTrigger::Execute) = 0;
		virtual bool UnsetBreakpoint(void* address) = 0;
		virtual bool IsBreakpointSet(void* address, BreakpointTrigger* outTrigger = nullptr) = 0;
	};

	static const char* const IDebugger_Version = "IDebugger_001";

	/* Assembles and executes CE and basm-style scripts. */
	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IAssembler
	{
	public:
		virtual bool Assemble(const char* script, bool forEnable) = 0;
		virtual void* GetSymbolAddress(const char* name) = 0;
		virtual void SetSymbolAddress(const char* name, void* address) = 0;
		virtual void EnableDataScans() = 0;
		virtual void DisableDataScans() = 0;
	};

	static const char* const IAssembler_Version = "IAssembler_001";

	class IHook
	{
	public:
		virtual void* TargetAddress() = 0;
		virtual void* DetourAddress() = 0;
		virtual void* OriginalAddress() = 0;
		virtual bool Enable() = 0;
		virtual bool Disable() = 0;
		virtual ~IHook() = 0;
	};

	/* Provides functionality for hooking high-level functions. */
	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IHooker
	{
	public:
		virtual IHook* Create(void* target, void* detour) = 0;
		virtual void BeginTransaction() = 0;
		virtual bool CommitTransaction() = 0;
	};

	static const char* const IHooker_Version = "IHooker_001";

	/* Allows you to interact with the mono runtime that is loaded into the game. */
	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IMonoRuntime
	{
	public:
		// Basic checks.
		virtual bool IsLoaded() = 0;
		virtual bool IsAssemblyLoaded(const char* name) = 0;
		virtual bool ClassExists(const char* assembly, const char* name_space, const char* klass) = 0;
		virtual bool MethodExists(const char* assembly, const char* name_space, const char* klass, const char* method, int numParams = -1) = 0;

		// Compiling methods.
		virtual bool CompileAssembly(const char* name) = 0;
		virtual bool CompileClass(const char* assembly, const char* name_space, const char* klass) = 0;
		virtual void* CompileMethod(const char* assembly, const char* name_space, const char* klass, const char* method, int numParams = -1) = 0;
	};

	static const char* const IMonoRuntime_Version = "IMonoRuntime_001";

	/* Provides methods to hook the UnrealEngine. */
	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IUnrealEvent
	{
	public:
		virtual void* GetObject() = 0;
		virtual const wchar_t* GetObjectName() = 0;
		virtual const wchar_t* GetFunctionName() = 0;
		virtual void** GetArguments() = 0;
		virtual uint8_t GetArgumentsLength() = 0;
		virtual void* CallNext() = 0;
	};

	class IUnrealEventHook
	{
	public:
		virtual void Enable() = 0;
		virtual void Disable() = 0;
		virtual bool Enabled() = 0;
		virtual ~IUnrealEventHook() = 0;
	};

	class IUnrealEventHandler
	{
	public:
		virtual void* Handle(IUnrealEvent* e) = 0;
		virtual ~IUnrealEventHandler() {};
	};

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class IUnrealEngine
	{
	public:
		virtual bool IsProcessUnreal() = 0;
		virtual IUnrealEventHook* HookEvent(const wchar_t* objectPattern, const wchar_t* functionPattern, IUnrealEventHandler* handler) = 0;
	};

	static const char* const IUnrealEngine_Version = "IUnrealEngine_001";

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class ITrainerLib
	{
	public:
		virtual void* GetInterface(const char* name) = 0;
	};

	class InterfaceFactory
	{
	public:
		InterfaceFactory()
		{
			Init(nullptr);
		}

		void Init(ITrainerLib* lib)
		{
			_lib = lib;
			_args = nullptr;
			_client = nullptr;
			_process = nullptr;
			_logger = nullptr;
			_taskManager = nullptr;
			_debugger = nullptr;
			_assembler = nullptr;
			_hooker = nullptr;
			_mono = nullptr;
		}

		template <typename T>
		T* GetInterface(const char* name)
		{
			return _lib != nullptr ? static_cast<T*>(_lib->GetInterface(name)) : nullptr;
		}

		ITrainerArgs& Args()
		{
			if (_args == nullptr) {
				_args = GetInterface<ITrainerArgs>(ITrainerArgs_Version);
			}
			return *_args;
		}

		IRemoteClient& Client()
		{
			if (_client == nullptr) {
				_client = GetInterface<IRemoteClient>(IRemoteClient_Version);
			}
			return *_client;
		}

		IProcess& Process()
		{
			if (_process == nullptr) {
				_process = GetInterface<IProcess>(IProcess_Version);
			}
			return *_process;
		}

		ILogger& Logger()
		{
			if (_logger == nullptr) {
				_logger = GetInterface<ILogger>(ILogger_Version);
			}
			return *_logger;
		}

		ITaskManager& TaskManager()
		{
			if (_taskManager == nullptr) {
				_taskManager = GetInterface<ITaskManager>(ITaskManager_Version);
			}
			return *_taskManager;
		}

		IDebugger& Debugger()
		{
			if (_debugger == nullptr) {
				_debugger = GetInterface<IDebugger>(IDebugger_Version);
			}
			return *_debugger;
		}

		IAssembler& Assembler()
		{
			if (_assembler == nullptr) {
				_assembler = GetInterface<IAssembler>(IAssembler_Version);
			}
			return *_assembler;
		}

		IHooker& Hooker()
		{
			if (_hooker == nullptr) {
				_hooker = GetInterface<IHooker>(IHooker_Version);
			}
			return *_hooker;
		}

		IMonoRuntime& MonoRuntime()
		{
			if (_mono == nullptr) {
				_mono = GetInterface<IMonoRuntime>(IMonoRuntime_Version);
			}
			return *_mono;
		}

		IUnrealEngine& UnrealEngine()
		{
			if (_unrealEngine == nullptr) {
				_unrealEngine = GetInterface<IUnrealEngine>(IUnrealEngine_Version);
			}
			return *_unrealEngine;
		}

	private:
		ITrainerLib* _lib;
		ITrainerArgs* _args;
		IRemoteClient* _client;
		IProcess* _process;
		ILogger* _logger;
		ITaskManager* _taskManager;
		IDebugger* _debugger;
		IAssembler* _assembler;
		IHooker* _hooker;
		IMonoRuntime* _mono;
		IUnrealEngine* _unrealEngine;
	};

	extern InterfaceFactory Factory;

	class Log
	{
	public:
		void operator()(std::wstring message, ...) const
		{
			va_list va;
			va_start(va, message);

			wchar_t szMessage[4096];
			vswprintf_s(szMessage, message.c_str(), va);
			szMessage[4095] = 0;

			Factory.Logger().Log(LogLevel::Info, szMessage);
		}

		void operator()(LogLevel level, std::wstring message, ...) const
		{
			va_list va;
			va_start(va, message);

			wchar_t szMessage[4096];
			vswprintf_s(szMessage, message.c_str(), va);
			szMessage[4095] = 0;

			Factory.Logger().Log(level, szMessage);
		}

		void operator()(std::string message, ...) const
		{
			va_list va;
			va_start(va, message);

			char szMessage[4096];
			vsprintf_s(szMessage, message.c_str(), va);
			szMessage[4095] = 0;

			message = std::string(szMessage);

			(*this)(LogLevel::Info, std::wstring(message.begin(), message.end()).c_str());
		}

		void operator()(LogLevel level, std::string message, ...) const
		{
			va_list va;
			va_start(va, message);

			char szMessage[4096];
			vsprintf_s(szMessage, message.c_str(), va);
			szMessage[4095] = 0;

			message = std::string(szMessage);

			(*this)(level, std::wstring(message.begin(), message.end()).c_str());
		}

		Log& operator<<(std::wstring message)
		{
			(*this)(message);
			return *this;
		}

		Log& operator<<(std::string message)
		{
			(*this)(message);
			return *this;
		}
	};

	class TrainerArgs final
	{
		std::set<std::string> _flags;

		// Remove spaces and split flags by a comma.
		void InitFlags()
		{
			std::string str = Factory.Args().GetFlags();
			str.erase(remove_if(str.begin(), str.end(), isspace), str.end());

			std::set<std::string> flags;

			std::stringstream stream(str);
			std::string item;
			while (getline(stream, item, ',')) {
				flags.insert(item);
			}

			flags.erase("");

			_flags = flags;
		}

	public:
		// ReSharper disable once CppMemberFunctionMayBeStatic
		uint32_t GameVersion() const
		{
			return Factory.Process().GetModuleTimestamp();
		}

		bool IsGameVersion(uint32_t version) const
		{
			return GameVersion() == version;
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		bool HasFlags() const
		{
			return !std::string(Factory.Args().GetFlags()).empty();
		}

		bool HasFlag(std::string flag)
		{
			InitFlags();

			return _flags.find(flag) != _flags.end();
		}
	};

	class HookManager final
	{
	public:
		template <typename TFunc>
		class Hook final
		{
			friend class HookManager;

			IHook* _hook;

		protected:
			explicit Hook(IHook* hook)
				: _hook(hook) { }

		public:
			const TFunc Target = TFunc(_hook->TargetAddress());
			const TFunc Detour = TFunc(_hook->DetourAddress());
			const TFunc Original = TFunc(_hook->OriginalAddress());

			void* TargetAddress() const
			{
				return _hook->TargetAddress();
			}

			void* DetourAddress() const
			{
				return _hook->DetourAddress();
			}

			void* OriginalAddress() const
			{
				return _hook->OriginalAddress();
			}

			bool Enable() const
			{
				return _hook->Enable();
			}

			bool Disable() const
			{
				return _hook->Disable();
			}

			~Hook()
			{
				delete _hook;
			}
		};

		template <typename TTarget, typename TFunc>
		Hook<TFunc>* Create(TTarget target, TFunc detour)
		{
			if (target == nullptr) {
				return nullptr;
			}

			auto hook = Factory.Hooker().Create(static_cast<void*>(target), detour);

			return hook == nullptr ? nullptr : new Hook<TFunc>(hook);
		}

		template <typename TFunc>
		Hook<TFunc>* Create(const char* searchTerms, TFunc detour)
		{
			return Create(Factory.Process().ScanModule(searchTerms), detour);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void BeginTransaction() const
		{
			Factory.Hooker().BeginTransaction();
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		bool CommitTransaction() const
		{
			return Factory.Hooker().CommitTransaction();
		}
	};

	class ModuleCollection
	{
	public:
		class Module final
		{
			friend class ModuleCollection;

			std::wstring _name;
			uint8_t* _base = nullptr;

		protected:
			explicit Module()
				: _name(L"") { }

			explicit Module(const char* name)
				: Module(std::string(name == nullptr ? "" : name)) { }

			explicit Module(const wchar_t* name)
				: _name(name == nullptr ? L"" : name) { }

			explicit Module(std::wstring name)
				: _name(name) { }

			explicit Module(std::string name)
				: _name(std::wstring(name.begin(), name.end())) { }

		public:
			std::wstring Name() const
			{
				if (!_name.empty()) {
					return _name;
				}

				auto name = Factory.Process().GetMainModuleBaseName();
				std::wstring str = name;
				delete name;
				return str;
			}

			uint8_t* Base()
			{
				return _base != nullptr ? _base : _base = static_cast<uint8_t*>(
					Factory.Process().GetModuleBaseAddress(_name.empty() ? nullptr : _name.c_str()));
			}

			bool Exists()
			{
				return Base() != nullptr;
			}

			HMODULE Handle()
			{
				return HMODULE(Base());
			}

			IMAGE_DOS_HEADER* DosHeader()
			{
				return reinterpret_cast<IMAGE_DOS_HEADER*>(Base());
			}

			IMAGE_NT_HEADERS* PeHeader()
			{
				return reinterpret_cast<IMAGE_NT_HEADERS*>(Base() + DosHeader()->e_lfanew);
			}

			uint32_t Timestamp()
			{
				return PeHeader()->FileHeader.TimeDateStamp;
			}

			template <typename T>
			uint8_t* Abs(T rva)
			{
				return Base() + static_cast<intptr_t>(rva);
			}

			template <typename T>
			uint8_t* Rva(T abs)
			{
				return static_cast<uint8_t*>(abs) - reinterpret_cast<intptr_t>(Base());
			}

			template <typename T>
			uint8_t* Scan(const char* terms, T startAddress)
			{
				return static_cast<uint8_t*>(Factory.Process().ScanModule(
					terms, _name.empty() ? nullptr : _name.c_str(), static_cast<void*>(startAddress)));
			}

			uint8_t* Scan(const char* terms)
			{
				return Scan(terms, static_cast<void*>(nullptr));
			}

			template <typename TReturn>
			TReturn Scan(const char* terms)
			{
				return static_cast<TReturn>(Scan(terms, static_cast<void*>(nullptr)));
			}

			template <typename TReturn, typename TOffset>
			TReturn Scan(const char* terms, TOffset offset)
			{
				auto address = Scan(terms);
				return address != nullptr
					? reinterpret_cast<TReturn>(address + static_cast<intptr_t>(offset))
					: nullptr;
			}
		};

		Module Main;

		template <typename TName>
		Module operator[](TName name) const
		{
			return Module(name);
		}
	};

	class Process
	{
	public:
		// ReSharper disable once CppMemberFunctionMayBeStatic
		uint8_t* Scan(const char* terms) const
		{
			return static_cast<uint8_t*>(Factory.Process().ScanProcess(terms, nullptr, nullptr));
		}

		template <typename T>
		uint8_t* Scan(const char* terms, T startAddress, T endAddress = nullptr)
		{
			return static_cast<uint8_t*>(Factory.Process().ScanProcess(
				terms, static_cast<void*>(startAddress), static_cast<void*>(endAddress)));
		}

		template <typename TValue>
		class FreezeTaskRoutine : public ITaskRoutine
		{
			TValue* _address;
			TValue _value;
			uint32_t _interval;

		public:
			FreezeTaskRoutine(TValue* address, TValue value, uint32_t interval)
				: _address(address), _value(value), _interval(interval) { }

			void Execute(ITask* task) override
			{
				while (!task->ShouldEnd()) {
					*_address = _value;
					Sleep(_interval);
				}
			}

			virtual ~FreezeTaskRoutine() { }
		};

		template <typename TAddress, typename TValue>
		ITask* FreezeValue(TAddress address, TValue value, uint32_t interval = 100)
		{
			return Factory.TaskManager().CreateTask(new FreezeTaskRoutine<TValue>(
				reinterpret_cast<TValue*>(address), value, interval));
		}
	};

	class Assembler
	{
	public:
		class SymbolWrapper final
		{
			friend class Assembler;

			Assembler& _assembler;
			std::string _symbolName;

		protected:
			SymbolWrapper(Assembler& assembler, std::string symbolName)
				: _assembler(assembler), _symbolName(symbolName) { }

		public:
			template <typename TValue>
			const SymbolWrapper& operator=(TValue value) const
			{
				auto address = static_cast<TValue*>(_assembler.GetAddress(_symbolName.c_str()));

				if (address != nullptr) {
					*address = value;
				}

				return *this;
			}

			void* Address() const
			{
				return _assembler.GetAddress(_symbolName.c_str());
			}

			template <typename T>
			T As() const
			{
				auto address = static_cast<T*>(_assembler.GetAddress(_symbolName.c_str()));

				return address == nullptr ? T() : *address;
			}

			template <typename T>
			ITask* Freeze(T value, uint32_t interval = 100)
			{
				return _assembler.Freeze(_symbolName.c_str(), value, interval);
			}
		};

		SymbolWrapper operator[](const char* symbolName)
		{
			return SymbolWrapper(*this, symbolName);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void* GetAddress(const char* symbolName) const
		{
			return Factory.Assembler().GetSymbolAddress(symbolName);
		}

		template <typename TAddress>
		TAddress GetAddress(const char* symbolName) const
		{
			return static_cast<TAddress>(GetAddress(symbolName));
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		bool Assemble(const char* script, bool enable = true) const
		{
			return Factory.Assembler().Assemble(script, enable);
		}

		bool operator<<(const char* script) const
		{
			return Assemble(script, true);
		}

		bool operator >> (const char* script) const
		{
			return Assemble(script, false);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void EnableDataScans() const
		{
			return Factory.Assembler().EnableDataScans();
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void DisableDataScans() const
		{
			return Factory.Assembler().DisableDataScans();
		}

		template <typename TValue>
		ITask* Freeze(const char* name, TValue value, uint32_t interval = 100)
		{
			auto addr = reinterpret_cast<TValue*>(GetAddress(name));

			if (addr == nullptr) {
				return nullptr;
			}

			return Factory.TaskManager().CreateTask(new Process::FreezeTaskRoutine<TValue>(addr, value, interval));
		}
	};

	// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
	class BreakpointManager : IBreakpointHandler
	{
		using BreakpointHandlerT = std::function<bool(PCONTEXT)>;

	public:
		class Breakpoint final
		{
			friend class BreakpointManager;

			void* _address;
			uintptr_t _onlyAt = 0;
			bool _enabled = false;
			int _hasHandler = false;
			int _hasPostHandler = false;
			BreakpointHandlerT _handler;
			BreakpointHandlerT _postHandler;
			BreakpointTrigger _trigger = BreakpointTrigger::Execute;

			Breakpoint(Breakpoint const &) = delete;
			void operator=(Breakpoint const &x) = delete;

		protected:
			explicit Breakpoint(void* address)
				: _address(address) { }

		public:
			void* Address() const
			{
				return _address;
			}

			bool Valid() const
			{
				return _address != nullptr;
			}

			Breakpoint* SetHandler(BreakpointHandlerT handler)
			{
				_hasHandler = true;
				_handler = handler;
				return this;
			}

			Breakpoint* SetPostHandler(BreakpointHandlerT handler)
			{
				_hasPostHandler = true;
				_postHandler = handler;
				return this;
			}

			void RemoveHandler()
			{
				_hasHandler = false;
			}

			void RemovePostHandler()
			{
				_hasPostHandler = false;
			}

			Breakpoint* SetTrigger(BreakpointTrigger trigger)
			{
				_trigger = trigger;
				return this;
			}

			bool Enabled() const
			{
				return _enabled;
			}

			bool Enable()
			{
				return _enabled || Valid() && ((_enabled = Factory.Debugger().SetBreakpoint(_address, _trigger)));
			}

			void Disable()
			{
				if (!_enabled) {
					return;
				}

				_enabled = false;

				Factory.Debugger().UnsetBreakpoint(_address);
			}

			void* OnlyAt() const
			{
				return reinterpret_cast<void*>(_onlyAt);
			}

			template <typename TAddress>
			Breakpoint* OnlyAt(TAddress address)
			{
				_onlyAt = uintptr_t(address);
				return this;
			}

			Breakpoint* OnlyAt(const Assembler::SymbolWrapper& symbol)
			{
				return OnlyAt(symbol.As<void*>());
			}

			Breakpoint* OnlyAt(const char* searchTerms, intptr_t offset = 0)
			{
				auto address = Factory.Process().ScanModule(searchTerms, nullptr, nullptr);

				if (address != nullptr) {
					address = reinterpret_cast<void*>(intptr_t(address) + offset);
				}

				return OnlyAt(address);
			}

			bool Call(PCONTEXT context) const
			{
				if (!_enabled || !_hasHandler) {
					return true;
				}

#ifdef _M_X64
				if (_onlyAt != 0 && context->Rip != _onlyAt) {
					return true;
				}
#else
				if (_onlyAt != 0 && context->Eip != _onlyAt) {
					return true;
				}
#endif

				return _handler(context);
			}

			bool CallPost(PCONTEXT context) const
			{
				return !_enabled || !_hasPostHandler || _postHandler(context);
			}

			template <typename TAddress>
			Breakpoint* SetDetour(TAddress detour)
			{
				return SetHandler([detour](PCONTEXT context) {
#ifdef _M_X64
					context->Rip = uintptr_t(detour);
#else
					context->Eip = uintptr_t(detour);
#endif
					return true;
				});
			}

			Breakpoint* SetDetour(const Assembler::SymbolWrapper& symbol)
			{
				return SetDetour(symbol.As<void*>());
			}
		};

	private:
		std::mutex _handlerLock;
		std::map<void*, Breakpoint*> _handlers;
		bool _registered = false;

		bool HandleBreakpoint(void* address, uint32_t, PCONTEXT context, bool post) override
		{
			for (auto& handler : _handlers) {
				if (handler.first == address && (!post && handler.second->Call(context) || post && handler.second->CallPost(context))) {
					return true;
				}
			}

			return false;
		}

	public:
		Breakpoint* At(void* lpAddress)
		{
			_handlerLock.lock();

			if (!_registered) {
				_registered = true;
				Factory.Debugger().AddBreakpointHandler(this);
			}

			auto existing = _handlers.find(lpAddress);

			if (existing == _handlers.end()) {
				_handlers.insert({ lpAddress, new Breakpoint(lpAddress) });
				existing = _handlers.find(lpAddress);
			}

			_handlerLock.unlock();

			return existing->second;
		}

		Breakpoint* operator[](void* lpAddress)
		{
			return At(lpAddress);
		}

		template <typename TAddress>
		Breakpoint* operator[](TAddress lpAddress)
		{
			return At(reinterpret_cast<void*>(lpAddress));
		}

		Breakpoint* operator[](Assembler::SymbolWrapper symbol)
		{
			return At(symbol.As<void*>());
		}

		Breakpoint* operator[](const char* searchTerms)
		{
			return At(Factory.Process().ScanModule(searchTerms, nullptr, nullptr));
		}

		~BreakpointManager()
		{
			if (_registered) {
				auto debugger = &Factory.Debugger();
				if (debugger != nullptr) {
					debugger->RemoveBreakpointHandler(this);
				}
			}
		}
	};

	class ValueManager final
	{
	public:
		class VarWrapper final
		{
			friend class ValueManager;

			std::string _varName;

		protected:
			explicit VarWrapper(std::string varName)
				: _varName(varName) { }

		public:
			template <typename TValue>
			const VarWrapper& operator=(TValue value) const
			{
				Factory.Client().SetValue(_varName.c_str(), static_cast<double>(value));
				return *this;
			}

			const VarWrapper& operator=(bool value) const
			{
				Factory.Client().SetValue(_varName.c_str(), value ? 1 : 0);
				return *this;
			}

			operator double() const
			{
				return Factory.Client().GetValue(_varName.c_str());
			}

			operator bool() const
			{
				return Factory.Client().GetValue(_varName.c_str()) != 0;
			}

			operator float() const
			{
				return static_cast<float>(Factory.Client().GetValue(_varName.c_str()));
			}

			operator uint32_t() const
			{
				return static_cast<uint32_t>(Factory.Client().GetValue(_varName.c_str()));
			}

			template <typename T>
			T As() const
			{
#pragma warning(push)
#pragma warning(disable:4800)
				return static_cast<T>(Factory.Client().GetValue(_varName.c_str()));
#pragma warning(pop)
			}
		};

		VarWrapper operator[] (const char* varName) const
		{
			return VarWrapper(varName);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		double Get(const char* varName) const
		{
			return Factory.Client().GetValue(varName);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void Set(const char* varName, double value) const
		{
			Factory.Client().SetValue(varName, value);
		}
	};

	class HandlerManager : public IValueChangedHandler
	{
	public:
		using ValueHandlerT = std::function<void(double)>;
		using GlobalValueHandlerT = std::function<void(std::string, double)>;

		class HandlerWrapper
		{
			HandlerManager& _manager;
			std::string _varName;

		public:
			HandlerWrapper(HandlerManager& manager, std::string varName)
				: _manager(manager), _varName(varName) { }

			HandlerWrapper& operator+= (ValueHandlerT handler)
			{
				_manager.Initialize();

				auto handlers = _manager._varHandlers.find(_varName);

				if (handlers == _manager._varHandlers.end()) {
					_manager._varHandlers[_varName] = std::list<ValueHandlerT>{ handler };
				} else {
					handlers->second.push_back(handler);
				}

				return *this;
			}

			template <typename TFunc>
			HandlerWrapper& operator+= (HookManager::Hook<TFunc>* hook)
			{
				return this->operator+=([hook](auto value) {
					if (value == 0) {
						hook->Disable();
					} else {
						hook->Enable();
					}
				});
			}

			HandlerWrapper& operator+= (IUnrealEventHook* hook)
			{
				return this->operator+=([hook](auto value) {
					if (value == 0) {
						hook->Disable();
					} else {
						hook->Enable();
					}
				});
			}

			HandlerWrapper& operator+= (const char* aaScript)
			{
				auto varName = _varName;

				return this->operator+=([varName, aaScript](auto value) {
					if (!Factory.Assembler().Assemble(aaScript, value != 0)) {
						Factory.Client().SetValue(varName.c_str(), value != 0 ? 0 : 1);
					}
				});
			}

			HandlerWrapper& operator+= (BreakpointManager::Breakpoint* breakpoint)
			{
				auto varName = _varName;

				return this->operator+=([varName, breakpoint](auto value) {
					if (value == 0) {
						breakpoint->Disable();
					} else if (!breakpoint->Enable()) {
						Factory.Client().SetValue(varName.c_str(), 0);
					}
				});
			}

			void RemoveAll() const
			{
				_manager._varHandlers.erase(_varName);
			}
		};

	private:
		bool _initialized = false;
		std::map<std::string, std::list<ValueHandlerT>> _varHandlers;
		std::list<GlobalValueHandlerT> _globalHandlers;

		void Initialize()
		{
			if (!_initialized) {
				_initialized = true;
				Factory.Client().AddValueChangedHandler(this);
			}
		}

	public:
		HandlerWrapper operator[] (const char* varName)
		{
			return HandlerWrapper(*this, varName);
		}

		HandlerManager& operator+= (GlobalValueHandlerT handler)
		{
			Initialize();
			_globalHandlers.push_back(handler);
			return *this;
		}

		void HandleValueChanged(const char* varName, double value) override
		{
			auto& client = Factory.Client();

			for (auto handler : _globalHandlers) {
				handler(varName, value);
				if (client.GetValue(varName) != value) {
					return;
				}
			}

			auto handlers = _varHandlers.find(varName);

			if (handlers != _varHandlers.end()) {
				for (auto& handler : handlers->second) {
					handler(value);
					if (client.GetValue(varName) != value) {
						return;
					}
				}
			}
		}

		virtual ~HandlerManager()
		{
			if (_initialized) {
				Factory.Client().RemoveValueChangedHandler(this);
			}
		}
	};

	class MonoRuntime
	{
	public:
		class MethodWrapper;
		class ClassWrapper;

		class AssemblyWrapper
		{
			friend class ClassWrapper;
			friend class MethodWrapper;

			std::string _name;

		public:
			explicit AssemblyWrapper(std::string name)
				: _name(name) { }

			std::string Name() const
			{
				return _name;
			}

			bool Loaded() const
			{
				return Factory.MonoRuntime().IsAssemblyLoaded(_name.c_str());
			}

			bool Compile() const
			{
				return Factory.MonoRuntime().CompileAssembly(_name.c_str());
			}

			ClassWrapper operator[](const char* fullClassName)
			{
				std::string fullClass = fullClassName;

				auto x = fullClass.find_last_of(".");

				if (x == std::string::npos || x >= fullClass.size() - 1) {
					return ClassWrapper(*this, "", fullClassName);
				}

				return ClassWrapper(*this,
					fullClass.substr(0, x),
					fullClass.substr(x + 1));
			}
		};

		class ClassWrapper
		{
			AssemblyWrapper& _assembly;
			std::string _namespace;
			std::string _name;

		public:
			ClassWrapper(AssemblyWrapper& assembly, std::string namespaceName, std::string name)
				: _assembly(assembly), _namespace(namespaceName), _name(name) { }

			AssemblyWrapper& Assembly() const
			{
				return _assembly;
			}

			std::string FullName() const
			{
				return _namespace.empty() ? _name : (_namespace + "." + _name);
			}

			std::string Namespace() const
			{
				return _namespace;
			}

			std::string Name() const
			{
				return _name;
			}

			bool Exists() const
			{
				return Factory.MonoRuntime().ClassExists(_assembly.Name().c_str(), _namespace.c_str(), _name.c_str());
			}

			bool Compile() const
			{
				return Factory.MonoRuntime().CompileClass(_assembly.Name().c_str(), _namespace.c_str(), _name.c_str());
			}

			MethodWrapper operator[](const char* methodName)
			{
				return MethodWrapper(*this, methodName);
			}
		};

		class MethodWrapper
		{
			ClassWrapper& _class;
			std::string _name;

		public:
			MethodWrapper(ClassWrapper& classWrapper, std::string name)
				: _class(classWrapper), _name(name) { }

			AssemblyWrapper& Assembly() const
			{
				return _class.Assembly();
			}

			ClassWrapper& Class() const
			{
				return _class;
			}

			std::string Name() const
			{
				return _name;
			}

			bool Exists(int numParams = -1) const
			{
				return Factory.MonoRuntime().MethodExists(Assembly().Name().c_str(),
					_class.Namespace().c_str(), _class.Name().c_str(), _name.c_str(), numParams);
			}

			void* Compile(int numParams = -1) const
			{
				return Factory.MonoRuntime().CompileMethod(Assembly().Name().c_str(),
					_class.Namespace().c_str(), _class.Name().c_str(), _name.c_str(), numParams);
			}

			template <typename TFunc>
			TFunc Compile(int numParams = -1) const
			{
				return TFunc(Compile(numParams));
			}

			uintptr_t Address() const
			{
				return uintptr_t(Compile());
			}

			operator uintptr_t() const
			{
				return Address();
			}
		};

		AssemblyWrapper operator[](const char* assemblyName) const
		{
			return AssemblyWrapper(assemblyName);
		}

		bool AssemblyLoaded(const char* assemblyName) const
		{
			return Runtime().IsAssemblyLoaded(assemblyName);
		}

		bool Loaded() const
		{
			return Runtime().IsLoaded();
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		IMonoRuntime& Runtime() const
		{
			return Factory.MonoRuntime();
		}
	};

	class Wait
	{
		MonoRuntime& _mono;

	public:
		explicit Wait(MonoRuntime& mono)
			: _mono(mono)
		{

		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void Until(std::function<bool(void)> func, uint32_t interval) const
		{
			while (!func()) {
				Sleep(interval);
			}
		}

		template <typename T>
		void UntilNull(T*& ptr, uint32_t interval = 100)
		{
			Until([&ptr]() { return ptr == nullptr; }, interval);
		}

		template <typename T>
		void UntilNotNull(T*& ptr, uint32_t interval = 100)
		{
			Until([&ptr]() { return ptr != nullptr; }, interval);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void* UntilModuleContains(const char* terms, uint32_t interval = 2500) const
		{
			void* addr = nullptr;

			Until([terms, &addr]() { return (addr = Factory.Process().ScanModule(terms)) != nullptr; }, interval);

			return addr;
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void* UntilProcessContains(const char* terms, uint32_t interval = 2500) const
		{
			void* addr = nullptr;

			Until([terms, &addr]() { return (addr = Factory.Process().ScanProcess(terms)) != nullptr; }, interval);

			return addr;
		}

		MonoRuntime& UntilMonoLoaded(uint32_t interval = 500) const
		{
			auto mono = &Factory.MonoRuntime();

			Until([mono]() { return mono->IsLoaded(); }, interval);

			return _mono;
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		MonoRuntime::AssemblyWrapper UntilMonoAssemblyLoaded(const char* assemblyName, uint32_t interval = 500) const
		{
			auto mono = &Factory.MonoRuntime();

			Until([mono, assemblyName]() { return mono->IsAssemblyLoaded(assemblyName); }, interval);

			return MonoRuntime::AssemblyWrapper(assemblyName);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void UntilDebuggerAttached(uint32_t interval = 500) const
		{
#ifdef _DEBUG
			while (!IsDebuggerPresent()) {
				Sleep(interval);
			}
#endif
		}
	};

	class TaskManager
	{
		using TaskRoutineT = std::function<void(ITask*)>;

		// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
		class RoutineWrapper : public ITaskRoutine
		{
		public:
			TaskRoutineT routine;

			void Execute(ITask* task) override
			{
				try {
					routine(task);
				}
				catch (...) {
					Factory.Logger().Log(LogLevel::Warning, L"Task routine threw an exception.");
				}
			}
		};

	public:
		ITask* operator+= (TaskRoutineT func) const
		{
			return Create(func);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		ITask* Create(TaskRoutineT func) const
		{
			auto routine = new RoutineWrapper();
			routine->routine = func;

			return Factory.TaskManager().CreateTask(routine);
		}

		ITask* Delay(uint32_t ms, TaskRoutineT func) const
		{
			return Create([ms, func](auto task) {
				Sleep(ms);
				if (!task->ShouldEnd()) {
					func(task);
				}
			});
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void EndAll() const
		{
			Factory.TaskManager().EndAllTasks();
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		void KillAll() const
		{
			Factory.TaskManager().TerminateAllTasks();
		}
	};

	class UnrealEngine
	{
	public:
		class EventArg
		{
			void* _address;

		public:
			EventArg(): _address(nullptr) {}

			explicit EventArg(void* address) : _address(address) {}

			bool Exists() const
			{
				return _address != nullptr;
			}

			template<typename T>
			T As() const
			{
				return *reinterpret_cast<T*>(_address);
			}

			template<typename T>
			const EventArg& operator=(T value) const
			{
				if (Exists()) {
					*reinterpret_cast<T*>(_address) = value;
				}

				return *this;
			}
		};

		class Event
		{
			IUnrealEvent* _event;

		public:
			EventArg Args[16];

			explicit Event(IUnrealEvent* e) : _event(e)
			{
				auto args = e->GetArguments();
				auto argLen = e->GetArgumentsLength();

				for (auto x = 0; x < argLen && x < 16; x++) {
					Args[x] = EventArg(args[x]);
				}
			}

			template<typename TObject>
			TObject* Object()
			{
				return reinterpret_cast<TObject*>(_event->GetObject());
			}

			std::wstring ObjectName() const
			{
				return std::wstring(_event->GetObjectName());
			}

			std::wstring FunctionName() const
			{
				return std::wstring(_event->GetFunctionName());
			}

			uint8_t ArgCount() const
			{
				return _event->GetArgumentsLength();
			}

			void* Next() const
			{
				return _event->CallNext();
			}
		};

		using EventHandlerT = std::function<void*(Event& e)>;

		// ReSharper disable once CppPolymorphicClassWithNonVirtualPublicDestructor
		class EventHandler : public IUnrealEventHandler
		{
			EventHandlerT _handler;

		public:
			explicit EventHandler(EventHandlerT handler) : _handler(handler) {}

			void* Handle(IUnrealEvent* e) override
			{
				auto event = Event(e);

				return _handler(event);
			}
		};

		IUnrealEventHook* HookAllEvents(EventHandlerT handler) const
		{
			return HookEvent(L"*", L"*", handler);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		IUnrealEventHook* HookEvent(std::string objectNamePattern, std::string functionNamePattern, EventHandlerT handler) const
		{
			return HookEvent(
				std::wstring(objectNamePattern.begin(), objectNamePattern.end()).c_str(),
				std::wstring(functionNamePattern.begin(), functionNamePattern.end()).c_str(),
				handler);
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		IUnrealEventHook* HookEvent(std::wstring objectNamePattern, std::wstring functionNamePattern, EventHandlerT handler) const
		{
			return Factory.UnrealEngine().HookEvent(objectNamePattern.c_str(), functionNamePattern.c_str(), new EventHandler(handler));
		}

		// ReSharper disable once CppMemberFunctionMayBeStatic
		bool Supported() const
		{
			return Factory.UnrealEngine().IsProcessUnreal();
		}
	};

	using GameVersionSetupT = void(*)(void);
	extern std::map<uint32_t, GameVersionSetupT> GameVersionSetups;

	static GameVersionSetupT RegisterGameVersionSetup(GameVersionSetupT setup, ...)
	{
		va_list va;
		va_start(va, setup);

		uint32_t timestamp;
		while ((timestamp = va_arg(va, uint32_t)) != 0xffffffff) {
			GameVersionSetups[timestamp] = setup;
		}

		return setup;
	}

	static void CallGameVersionSetup()
	{
		auto versionSetup = GameVersionSetups.find(Factory.Process().GetModuleTimestamp());

		if (versionSetup == GameVersionSetups.end()) {
			versionSetup = GameVersionSetups.find(0);
		}

		if (versionSetup != GameVersionSetups.end()) {
			versionSetup->second();
		}
	}
}

extern TrainerLib::Log Log;
extern TrainerLib::MonoRuntime Mono;
extern TrainerLib::ValueManager Values;
extern TrainerLib::Assembler Assembler;
extern TrainerLib::Assembler& Symbols;
extern TrainerLib::Process Process;
extern TrainerLib::ModuleCollection Modules;
extern TrainerLib::ModuleCollection::Module& MainModule;
extern TrainerLib::BreakpointManager Breakpoints;
extern TrainerLib::HookManager Hooks;
extern TrainerLib::HandlerManager Handlers;
extern TrainerLib::TrainerArgs Trainer;
extern TrainerLib::Wait Wait;
extern TrainerLib::TaskManager Tasks;
extern TrainerLib::UnrealEngine UE;

template <typename TFunc>
using Hook = TrainerLib::HookManager::Hook<TFunc>*;
using Module = TrainerLib::ModuleCollection::Module;
using Task = TrainerLib::ITask*;
using LogLevel = TrainerLib::LogLevel;
using Breakpoint = TrainerLib::BreakpointManager::Breakpoint*;
using BreakpointTrigger = TrainerLib::BreakpointTrigger;
using UEvent = TrainerLib::UnrealEngine::Event;

// __stdcall
#define STDCALL __stdcall
template <typename TReturn, typename ...TArgs>
using TStdCall = TReturn(__stdcall*)(TArgs...);

// __fastcall
#define FASTCALL __fastcall
template <typename TReturn, typename ...TArgs>
using TFastCall = TReturn(__fastcall*)(TArgs...);

template <typename TReturn, typename ...TArgs>
TFastCall<TReturn, TArgs...> FastCall(void* address)
{
	return static_cast<TFastCall<TReturn, TArgs...>>(address);
}

// __thiscall
#define THISCALL __thiscall
template <typename TReturn, typename ...TArgs>
using TThisCall = TReturn(__thiscall*)(TArgs...);

// __cdecl
#undef CDECL
#define CDECL __cdecl
template <typename TReturn, typename ...TArgs>
using TCDeclCall = TReturn(__cdecl*)(TArgs...);
template <typename TReturn, typename ...TArgs>
TCDeclCall<TReturn, TArgs...> CDeclCall(void* address)
{
	return static_cast<TCDeclCall<TReturn, TArgs...>>(address);
}
// __vectorcall
#define VECTORCALL __vectorcall
template <typename TReturn, typename ...TArgs>
using TVectorCall = TReturn(__vectorcall*)(TArgs...);

/* Version Helpers */
#define Version(version) if (Trainer.IsGameVersion(version))
#define SetupVersion(version, ...) static void SetupGameVersion_ ##version(); \
static auto __gameVersionDef_ ##version = TrainerLib::RegisterGameVersionSetup(SetupGameVersion_ ##version, version, __VA_ARGS__, 0xffffffff); \
static void SetupGameVersion_ ##version()
#define SetupUnknownVersion() SetupVersion(0)

/* Struct Helpers */
#define GAME_STRUCT __pragma(pack(1)) union

#define FIELD(offset, type, name)	\
struct								\
{									\
	uint8_t name##_pad[offset];		\
	type name;						\
};									\


/* Log Helpers */
#define Debug(message, ...) Log(LogLevel::Debug, message, __VA_ARGS__)
#define Info(message, ...) Log(LogLevel::Info, message, __VA_ARGS__)
#define Warn(message, ...) Log(LogLevel::Warning, message, __VA_ARGS__)
#define Error(message, ...) Log(LogLevel::Error, message, __VA_ARGS__)

/* Mono Helpers */
#define Unity Mono["Assembly-CSharp"]

/* Assembler helpers */
#define AssembleScript(scriptName)		\
Log("Assembling "#scriptName##"...");	\
Assembler.Assemble(scriptName)

/* Breakpoint Helpers */
inline bool AwaitContext(void* address, std::function<void(PCONTEXT)> callback)
{
	auto breakpoint = Breakpoints[address];
	breakpoint->SetHandler([breakpoint, callback](PCONTEXT context) {
		breakpoint->Disable();
		callback(context);
		return true;
	});
	return breakpoint->Enable();
}

inline void AwaitContext(const char* searchTerms, std::function<void(PCONTEXT)> callback)
{
	AwaitContext(MainModule.Scan(searchTerms), callback);
}

#define AWAIT_FUNC_MASK(reg, name, type, mask)													\
inline bool Await##name##(void* address, std::function<void(type)> callback)					\
{																								\
	auto breakpoint = Breakpoints[address];														\
	breakpoint->SetHandler([breakpoint, callback](PCONTEXT context) {							\
		breakpoint->Disable();																	\
		callback(type(context->##reg) & mask);													\
		return true;																			\
	});																							\
	return breakpoint->Enable();																\
}																								\
																								\
inline void Await##name##(const char* searchTerms, std::function<void(type)> callback)			\
{																								\
	Await##name##(MainModule.Scan(searchTerms), callback);										\
}

#define AWAIT_FUNC_64(reg) AWAIT_FUNC_MASK(reg, reg, DWORD64, 0xffffffffffffffff)
#define AWAIT_FUNC_32(reg) AWAIT_FUNC_MASK(reg, reg, DWORD, 0xffffffff)
#define AWAIT_FUNC_16(reg) AWAIT_FUNC_MASK(reg, reg, WORD, 0xffff)
#define AWAIT_FUNC_8(reg) AWAIT_FUNC_MASK(reg, reg, BYTE, 0xff)

#ifdef _M_X64
#define AWAIT_FUNC_GEN(reg, l32, l16, l8)		\
AWAIT_FUNC_64(reg)								\
AWAIT_FUNC_MASK(reg, l32, DWORD, 0xffffffff)	\
AWAIT_FUNC_MASK(reg, l16, WORD, 0xffff)			\
AWAIT_FUNC_MASK(reg, l8, BYTE, 0xff)

AWAIT_FUNC_64(P1Home)
AWAIT_FUNC_64(P2Home)
AWAIT_FUNC_64(P3Home)
AWAIT_FUNC_64(P4Home)
AWAIT_FUNC_64(P5Home)
AWAIT_FUNC_64(P6Home)

AWAIT_FUNC_32(MxCsr)

AWAIT_FUNC_16(SegCs)
AWAIT_FUNC_16(SegDs)
AWAIT_FUNC_16(SegEs)
AWAIT_FUNC_16(SegFs)
AWAIT_FUNC_16(SegGs)
AWAIT_FUNC_16(SegSs)
AWAIT_FUNC_32(EFlags)

AWAIT_FUNC_64(Dr0)
AWAIT_FUNC_64(Dr1)
AWAIT_FUNC_64(Dr2)
AWAIT_FUNC_64(Dr3)
AWAIT_FUNC_64(Dr6)
AWAIT_FUNC_64(Dr7)

AWAIT_FUNC_GEN(Rax, Eax, Ax, Al)
AWAIT_FUNC_GEN(Rbx, Ebx, Bx, Bl)
AWAIT_FUNC_GEN(Rcx, Ecx, Cx, Cl)
AWAIT_FUNC_GEN(Rdx, Edx, Dx, Dl)
AWAIT_FUNC_GEN(Rsp, Esp, Sp, Spl)
AWAIT_FUNC_GEN(Rbp, Ebp, Bp, Bpl)
AWAIT_FUNC_GEN(Rsi, Esi, Si, Sil)
AWAIT_FUNC_GEN(Rdi, Edi, Di, Dil)
AWAIT_FUNC_GEN(R8, R8d, R8w, R8b)
AWAIT_FUNC_GEN(R9, R9d, R9w, R9b)
AWAIT_FUNC_GEN(R10, R10d, R10w, R10b)
AWAIT_FUNC_GEN(R11, R11d, R11w, R11b)
AWAIT_FUNC_GEN(R12, R12d, R12w, R12b)
AWAIT_FUNC_GEN(R13, R13d, R13w, R13b)
AWAIT_FUNC_GEN(R14, R14d, R14w, R14b)
AWAIT_FUNC_GEN(R15, R15d, R15w, R15b)
#else
#define AWAIT_FUNC_GEN(reg, l16, l8)			\
AWAIT_FUNC_MASK(reg, reg, DWORD, 0xffffffff)	\
AWAIT_FUNC_MASK(reg, l16, WORD, 0xffff)			\
AWAIT_FUNC_MASK(reg, l8, BYTE, 0xff)

AWAIT_FUNC_32(Dr0)
AWAIT_FUNC_32(Dr1)
AWAIT_FUNC_32(Dr2)
AWAIT_FUNC_32(Dr3)
AWAIT_FUNC_32(Dr6)
AWAIT_FUNC_32(Dr7)

AWAIT_FUNC_32(SegGs)
AWAIT_FUNC_32(SegFs)
AWAIT_FUNC_32(SegEs)
AWAIT_FUNC_32(SegDs)

AWAIT_FUNC_GEN(Eax, Ax, Al)
AWAIT_FUNC_GEN(Ebx, Bx, Bl)
AWAIT_FUNC_GEN(Ecx, Cx, Cl)
AWAIT_FUNC_GEN(Edx, Dx, Dl)
AWAIT_FUNC_GEN(Edi, Di, Dil)
AWAIT_FUNC_GEN(Esi, Si, Sil)

AWAIT_FUNC_32(Ebp)
AWAIT_FUNC_32(SegCs)
AWAIT_FUNC_32(EFlags)
AWAIT_FUNC_32(Esp)
AWAIT_FUNC_32(SegSs)
#endif

#undef AWAIT_FUNC_GEN
#undef AWAIT_FUNC_8
#undef AWAIT_FUNC_16
#undef AWAIT_FUNC_32
#undef AWAIT_FUNC_64
#undef AWAIT_FUNC_MASK

template <typename T>
uint8_t* ToRva(T abs, const char* moduleName = nullptr)
{
	return Modules[moduleName].Rva(abs);
}

template <typename T>
uint8_t* ToAbs(T rva, const char* moduleName = nullptr)
{
	return Modules[moduleName].Abs(rva);
}

#define Setup() void Setup();														\
	std::map<uint32_t, TrainerLib::GameVersionSetupT> TrainerLib::GameVersionSetups;\
	TrainerLib::InterfaceFactory TrainerLib::Factory;								\
	TrainerLib::Log Log;															\
	TrainerLib::MonoRuntime Mono;													\
	TrainerLib::ValueManager Values;												\
	TrainerLib::Assembler Assembler;												\
	TrainerLib::Assembler& Symbols = Assembler;										\
	TrainerLib::Process Process;													\
	TrainerLib::ModuleCollection Modules;											\
	TrainerLib::ModuleCollection::Module& MainModule = Modules.Main;				\
	TrainerLib::BreakpointManager Breakpoints;										\
	TrainerLib::HookManager Hooks;													\
	TrainerLib::HandlerManager Handlers;											\
	TrainerLib::TrainerArgs Trainer;												\
	TrainerLib::Wait Wait(Mono);													\
	TrainerLib::TaskManager Tasks;													\
	TrainerLib::UnrealEngine UE;													\
																					\
	extern "C" __declspec(dllexport) bool Initialize(TrainerLib::ITrainerLib* lib)	\
	{																				\
		TrainerLib::Factory.Init(lib);												\
		try {																		\
			Setup();																\
			TrainerLib::CallGameVersionSetup();										\
			return true;															\
		} catch (...) {																\
			TrainerLib::Factory.Logger().Log(										\
				LogLevel::Error, L"An exception was thrown in Setup().");			\
			return false;															\
		}																			\
	} void Setup()																	\

#define Cleanup() void Cleanup();													\
	extern "C" __declspec(dllexport) bool Clean()									\
	{																				\
		try {																		\
			Cleanup();																\
			return true;															\
		} catch (...) {																\
			TrainerLib::Factory.Logger().Log(										\
				LogLevel::Error, L"An exception was thrown in Cleanup().");			\
			return false;															\
		}																			\
	} void Cleanup()																\

#ifdef TRAINERLIB_V1
#define LOG_LEVEL_INFO		1
#define LOG_LEVEL_WARNING	2
#define LOG_LEVEL_ERROR		3
#define LOG_LEVEL_CRITICAL	4

#ifdef _DEBUG
#define VA_LOGW(_level)												\
va_list va;															\
va_start(va, format);												\
																	\
wchar_t szMessage[128];												\
vswprintf_s(szMessage, format, va);									\
szMessage[127] = 0;													\
																	\
Log(_level, szMessage);												\

#define VA_LOG(_level)												\
va_list va;															\
va_start(va, format);												\
																	\
char szMessage[256];												\
vsprintf_s(szMessage, format, va);									\
szMessage[255] = 0;													\
																	\
auto message = std::string(szMessage);								\
																	\
InfLogW(std::wstring(message.begin(), message.end()).c_str(), LogLevel::Info);
#else
#define VA_LOGW(_level)
#define VA_LOG(_level)
#endif

inline void InfLogW(LPCWSTR format, ...)
{
	VA_LOGW(LogLevel::Info)
}

inline void InfLogWEx(DWORD logLevel, LPCWSTR format, ...)
{
	VA_LOGW(static_cast<LogLevel>(logLevel))
}

inline void InfLog(LPCSTR format, ...)
{
	VA_LOG(LogLevel::Info)
}

inline void InfLogEx(DWORD logLevel, LPCSTR format, ...)
{
	VA_LOG((LogLevel)logLevel)
}

inline void WaitForDebugger()
{
	// Removed from v1 backwards compatibility.
}

// Memory leak, but it's never used in a loop.
inline LPCSTR InfGetGameVersion()
{
	auto version = new std::string(std::to_string(Trainer.GameVersion()));

	return version->c_str();
}

/****************************************************************************/

inline bool IsGameVersion(LPCSTR name)
{
	return name == std::to_string(Trainer.GameVersion());
}

inline LPVOID GetModuleBaseAddress(LPCWSTR moduleName = nullptr)
{
	return Modules[moduleName].Base();
}

// Adds the module base address to the given RVA.
// If moduleName is null, the process' main module will be used.
inline LPVOID RealAddress(LPVOID rva, LPCWSTR moduleName = nullptr)
{
	return LPVOID(uint64_t(Modules[moduleName].Base()) + uint64_t(rva));
}

template <typename T>
LPVOID RealAddressEx(T rva, LPCWSTR moduleName = nullptr)
{
	return RealAddress(reinterpret_cast<LPVOID>(static_cast<uint64_t>(rva)), moduleName);
}

// Short alias of RealAddressEx.
template <typename T>
LPVOID R(T rva, LPCWSTR moduleName = nullptr)
{
	return RealAddressEx(rva, moduleName);
}
// Short alias of RealAddressEx.
template <typename T>
LPVOID A(T rva, LPCWSTR moduleName = nullptr)
{
	return RealAddressEx(rva - INT64(GetModuleBaseAddress()), moduleName);
}

inline LPVOID SearchModule(LPCSTR terms, LPCSTR moduleName = nullptr, LPVOID startAddress = nullptr)
{
	return Modules[moduleName].Scan(terms, startAddress);
}

inline LPVOID SearchProcess(LPCSTR terms, LPVOID startAddress, LPVOID endAddress)
{
	return Process.Scan(terms, startAddress, endAddress);
}

/****************************************************************************/

typedef uint8_t byte;

#define INF_VAR_TYPE(fname, type)														\
																						\
typedef void(*##fname##HandlerT)(type);													\
																						\
inline void InfBind##fname (LPCSTR name, void(*handler)(type) = nullptr, type initialValue = 0)	\
{																						\
	if (double(initialValue) != 0) {													\
		Values[name] = type (initialValue);												\
	}																					\
																						\
	if (handler != nullptr) {															\
		Handlers[name] += [handler](auto value) {										\
			handler(type(value));														\
		};																				\
	}																					\
}																						\
																						\
inline void InfSet##fname (LPCSTR name, type val)										\
{																						\
	Values[name] = double(val);															\
}																						\
																						\
inline type InfGet##fname (LPCSTR name)													\
{																						\
	return Values[name].As<type>();														\
}																						\


#pragma warning(push)
#pragma warning(disable: 4244)
#pragma warning(push)
#pragma warning(disable: 4800)

INF_VAR_TYPE(Bool, bool)
INF_VAR_TYPE(Float, float)
INF_VAR_TYPE(Double, double)
INF_VAR_TYPE(Byte, byte)
INF_VAR_TYPE(Int16, int16_t)
INF_VAR_TYPE(UInt16, uint16_t)
INF_VAR_TYPE(Int32, int32_t)
INF_VAR_TYPE(UInt32, uint32_t)
INF_VAR_TYPE(Int64, int64_t)
INF_VAR_TYPE(UInt64, uint64_t)

#pragma warning(pop)
#pragma warning(pop)

typedef void(*AsciiStringHandlerT)(LPCSTR);
typedef void(*CommandHandlerT)();

inline void InfBindAsciiString(LPCSTR name, AsciiStringHandlerT handler = nullptr, LPCSTR initialValue = "")
{
	// not supported in v2.
}

inline void InfSetAsciiString(LPCSTR name, LPCSTR value)
{
	// not supported in v2.
}

inline LPCSTR InfGetAsciiString(LPCSTR name)
{
	return "";
}

inline void InfBindCommand(LPCSTR name, CommandHandlerT handler = nullptr)
{
	if (handler != nullptr) {
		Handlers[name] += [handler](auto value) {
			handler();
		};
	}
}

// Internally invokes a command mod.
inline void InfCallCommand(LPCSTR name)
{
	Handlers.HandleValueChanged(name, rand() % 100000);
}

/****************************************************************************/

inline ULONGLONG CeGetAddress(LPCSTR pszSymbol)
{
	return ULONGLONG(Assembler.GetAddress(pszSymbol));
}

inline bool CeAutoAssemble(LPCSTR pszScript, bool bEnable, bool bVerbose = false)
{
	return Assembler.Assemble(pszScript, bEnable);
}

inline void InfBindCommandToAaScript(LPCSTR name, LPCSTR script)
{
	Handlers[Assembler, name] += [script](auto value) {
		Assembler.Assemble(script, true);
	};
}

inline void InfBindBoolToAaScript(LPCSTR name, LPCSTR script, bool initialValue = false)
{
	if (initialValue) {
		Values[name] = 1;
	}

	Handlers[name] += [name, script](auto value) {
		if (!Assembler.Assemble(script, value != 0)) {
			Values[name] = value != 0 ? 0 : 1;
		}
	};
}

/****************************************************************************/

#define TRAINER_SETUP bool __TrainerSetup();			\
std::map<void*, TrainerLib::IHook*> __cachedHooks;		\
Setup()													\
{														\
	if (!__TrainerSetup()) throw "TrainerSetup failed";	\
} bool __TrainerSetup()

#define TRAINER_UNLOAD void __TrainerUnload();			\
Cleanup()												\
{														\
	__TrainerUnload();									\
} void __TrainerUnload()

extern std::map<void*, TrainerLib::IHook*> __cachedHooks;

/****************************************************************************/

/*
*  MinHook - The Minimalistic API Hooking Library for x64/x86
*  Copyright (C) 2009-2015 Tsuda Kageyu.
*  All rights reserved.
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*
*   1. Redistributions of source code must retain the above copyright
*      notice, this list of conditions and the following disclaimer.
*   2. Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
*  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
*  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
*  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
*  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
*  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
*  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
*  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
*  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// MinHook Error Codes.
typedef enum MX_STATUS
{
	// Unknown error. Should not be returned.
	MX_UNKNOWN = -1,

	// Successful.
	MX_OK = 0,

	// MinHook is already initialized.
	MX_ERROR_ALREADY_INITIALIZED = 1,

	// MinHook is not initialized yet, or already uninitialized.
	MX_ERROR_NOT_INITIALIZED = 2,

	// The hook for the specified target function is already created.
	MX_ERROR_ALREADY_CREATED = 3,

	// The hook for the specified target function is not created yet.
	MX_ERROR_NOT_CREATED = 4,

	// The hook for the specified target function is already enabled.
	MX_ERROR_ENABLED = 5,

	// The hook for the specified target function is not enabled yet, or already
	// disabled.
	MX_ERROR_DISABLED = 6,

	// The specified pointer is invalid. It points the address of non-allocated
	// and/or non-executable region.
	MX_ERROR_NOT_EXECUTABLE = 7,

	// The specified target function cannot be hooked.
	MX_ERROR_UNSUPPORTED_FUNCTION = 8,

	// Failed to allocate memory.
	MX_ERROR_MEMORY_ALLOC = 9,

	// Failed to change the memory protection.
	MX_ERROR_MEMORY_PROTECT = 10,

	// The specified module is not loaded.
	MX_ERROR_MODULE_NOT_FOUND = 11,

	// The specified function is not found.
	MX_ERROR_FUNCTION_NOT_FOUND = 12
} MX_STATUS;

inline MX_STATUS ConvertStatus(bool status)
{
	return status ? MX_OK : MX_UNKNOWN;
}

#define MX_ALL_HOOKS NULL

inline MX_STATUS MX_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal = nullptr)
{
	auto hook = TrainerLib::Factory.Hooker().Create(pTarget, pDetour);

	if (hook == nullptr) {
		return MX_UNKNOWN;
	}

	__cachedHooks[pTarget] = hook;

	if (ppOriginal != nullptr) {
		*ppOriginal = hook->OriginalAddress();
	}

	return MX_OK;
}

inline MX_STATUS MX_CreateHookApi(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal = nullptr)
{
	auto hModule = GetModuleHandleW(pszModule);

	if (hModule == nullptr) {
		return MX_ERROR_MODULE_NOT_FOUND;
	}

	auto lpProc = GetProcAddress(hModule, pszProcName);

	if (lpProc == nullptr) {
		return MX_ERROR_FUNCTION_NOT_FOUND;
	}

	return MX_CreateHook(lpProc, pDetour, ppOriginal);
}

inline MX_STATUS MX_RemoveHook(LPVOID pTarget)
{
	auto hookIter = __cachedHooks.find(pTarget);

	if (hookIter == __cachedHooks.end()) {
		return MX_ERROR_NOT_CREATED;
	}

	auto hook = hookIter->second;

	__cachedHooks.erase(pTarget);

	delete hook;

	return MX_OK;
}

inline MX_STATUS MX_EnableHook(LPVOID pTarget)
{
	auto hookIter = __cachedHooks.find(pTarget);

	if (hookIter == __cachedHooks.end()) {
		return MX_ERROR_NOT_CREATED;
	}

	return ConvertStatus(hookIter->second->Enable());
}

inline MX_STATUS MX_DisableHook(LPVOID pTarget)
{
	auto hookIter = __cachedHooks.find(pTarget);

	if (hookIter == __cachedHooks.end()) {
		return MX_ERROR_NOT_CREATED;
	}

	return ConvertStatus(hookIter->second->Disable());
}

inline MX_STATUS MX_QueueEnableHook(LPVOID pTarget)
{
	// No queue support.
	return MX_EnableHook(pTarget);
}

inline MX_STATUS MX_QueueDisableHook(LPVOID pTarget)
{
	// No queue support.
	return MX_DisableHook(pTarget);
}

inline MX_STATUS MX_ApplyQueued(VOID)
{
	return ConvertStatus(TrainerLib::Factory.Hooker().CommitTransaction());
}

inline MX_STATUS MX_SetHookState(LPVOID pTarget, bool enabled)
{
	if (enabled) {
		return MX_EnableHook(pTarget);
	}

	return MX_DisableHook(pTarget);
}

inline MX_STATUS MX_CreateAndEnableHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal = nullptr)
{
	auto status = MX_CreateHook(pTarget, pDetour, ppOriginal);

	if (status == MX_OK) {
		status = MX_EnableHook(pTarget);
	}

	return status;
}

inline MX_STATUS MX_CreateAndQueueEnableHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal = nullptr)
{
	auto status = MX_CreateHook(pTarget, pDetour, ppOriginal);

	if (status == MX_OK) {
		status = MX_QueueEnableHook(pTarget);
	}

	return status;
}

template <typename T>
MX_STATUS MX_CreateAndEnableHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
	return MX_CreateAndEnableHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
MX_STATUS MX_CreateAndQueueEnableHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
	return MX_CreateAndQueueEnableHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
MX_STATUS MX_CreateHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
	return MX_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
MX_STATUS MX_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	return MX_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

inline MX_STATUS InfBindBoolToHook(LPCSTR name, LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal = nullptr, bool initialValue = false)
{
	if (initialValue) {
		Values[name] = 1;
	}

	auto status = MX_CreateHook(pTarget, pDetour, ppOriginal);

	if (status != MX_OK) {
		return status;
	}

	Handlers[name] += [pTarget](auto value) {
		if (value != 0) {
			MX_EnableHook(pTarget);
		}
		else {
			MX_DisableHook(pTarget);
		}
	};

	return MX_OK;
}

template <typename T>
MX_STATUS InfBindBoolToHookEx(LPCSTR name, LPVOID pTarget, LPVOID pDetour, T** ppOriginal = nullptr, bool initialValue = false)
{
	return InfBindBoolToHook(name, pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal), initialValue);
}


/****************************************************************************/

// __stdcall

#define STDCALL __stdcall

template <typename TReturn>
using TStd_NoArgs = TReturn(__stdcall*)();

template <typename TReturn, typename TArg1>
using TStd_1Arg = TReturn(__stdcall*)(TArg1);

template <typename TReturn, typename TArg1, typename TArg2>
using TStd_2Args = TReturn(__stdcall*)(TArg1, TArg2);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3>
using TStd_3Args = TReturn(__stdcall*)(TArg1, TArg2, TArg3);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4>
using TStd_4Args = TReturn(__stdcall*)(TArg1, TArg2, TArg3, TArg4);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4, typename TArg5>
using TStd_5Args = TReturn(__stdcall*)(TArg1, TArg2, TArg3, TArg4, TArg5);


// __fastcall

#define FASTCALL __fastcall

template <typename TReturn>
using TFast_NoArgs = TReturn(__fastcall*)();

template <typename TReturn, typename TArg1>
using TFast_1Arg = TReturn(__fastcall*)(TArg1);

template <typename TReturn, typename TArg1, typename TArg2>
using TFast_2Args = TReturn(__fastcall*)(TArg1, TArg2);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3>
using TFast_3Args = TReturn(__fastcall*)(TArg1, TArg2, TArg3);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4>
using TFast_4Args = TReturn(__fastcall*)(TArg1, TArg2, TArg3, TArg4);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4, typename TArg5>
using TFast_5Args = TReturn(__fastcall*)(TArg1, TArg2, TArg3, TArg4, TArg5);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4, typename TArg5, typename TArg6>
using TFast_6Args = TReturn(__fastcall*)(TArg1, TArg2, TArg3, TArg4, TArg5, TArg6);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4, typename TArg5, typename TArg6, typename TArg7>
using TFast_7Args = TReturn(__fastcall*)(TArg1, TArg2, TArg3, TArg4, TArg5, TArg6, TArg7);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4, typename TArg5, typename TArg6, typename TArg7, typename TArg8, typename TArg9>
using TFast_9Args = TReturn(__fastcall*)(TArg1, TArg2, TArg3, TArg4, TArg5, TArg6, TArg7, TArg8, TArg9);


// __thiscall

#define THISCALL __thiscall

template <typename TReturn>
using TThis_NoArgs = TReturn(__thiscall*)();

template <typename TReturn, typename TArg1>
using TThis_1Arg = TReturn(__thiscall*)(TArg1);

template <typename TReturn, typename TArg1, typename TArg2>
using TThis_2Args = TReturn(__thiscall*)(TArg1, TArg2);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3>
using TThis_3Args = TReturn(__thiscall*)(TArg1, TArg2, TArg3);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4>
using TThis_4Args = TReturn(__thiscall*)(TArg1, TArg2, TArg3, TArg4);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4, typename TArg5>
using TThis_5Args = TReturn(__thiscall*)(TArg1, TArg2, TArg3, TArg4, TArg5);


// __cdecl

template <typename TReturn>
using TCDecl_NoArgs = TReturn(__cdecl*)();

template <typename TReturn, typename TArg1>
using TCDecl_1Arg = TReturn(__cdecl*)(TArg1);

template <typename TReturn, typename TArg1, typename TArg2>
using TCDecl_2Args = TReturn(__cdecl*)(TArg1, TArg2);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3>
using TCDecl_3Args = TReturn(__cdecl*)(TArg1, TArg2, TArg3);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4>
using TCDecl_4Args = TReturn(__cdecl*)(TArg1, TArg2, TArg3, TArg4);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4, typename TArg5>
using TCDecl_5Args = TReturn(__cdecl*)(TArg1, TArg2, TArg3, TArg4, TArg5);


// __vectorcall

#define VECTORCALL __vectorcall

template <typename TReturn>
using TVector_NoArgs = TReturn(__vectorcall*)();

template <typename TReturn, typename TArg1>
using TVector_1Arg = TReturn(__vectorcall*)(TArg1);

template <typename TReturn, typename TArg1, typename TArg2>
using TVector_2Args = TReturn(__vectorcall*)(TArg1, TArg2);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3>
using TVector_3Args = TReturn(__vectorcall*)(TArg1, TArg2, TArg3);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4>
using TVector_4Args = TReturn(__vectorcall*)(TArg1, TArg2, TArg3, TArg4);

template <typename TReturn, typename TArg1, typename TArg2, typename TArg3, typename TArg4, typename TArg5>
using TVector_5Args = TReturn(__vectorcall*)(TArg1, TArg2, TArg3, TArg4, TArg5);

#endif