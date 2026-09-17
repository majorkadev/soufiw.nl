#ifndef NEVELOSE_CSGO_MINI_H
#define NEVELOSE_CSGO_MINI_H
#include <phnt_windows.h>
#include <phnt.h>

typedef void* (*CreateInterfaceFn)(const char* pName, int* pReturnCode);

class IAppSystem
{
public:
	// Here's where the app systems get to learn about each other 
	virtual bool Connect(CreateInterfaceFn factory) = 0;
	virtual void Disconnect() = 0;

	// Here's where systems can access other interfaces implemented by this object
	// Returns NULL if it doesn't implement the requested interface
	virtual void* QueryInterface(const char* pInterfaceName) = 0;

	// Init, shutdown
	virtual DWORD Init() = 0;
	virtual void Shutdown() = 0;

	// Returns all dependent libraries
	virtual const PVOID GetDependencies() = 0;

	// Returns the tier
	virtual DWORD GetTier() = 0;

	// Reconnect to a particular interface
	virtual void Reconnect(CreateInterfaceFn factory, const char* pInterfaceName) {}
	// Is this appsystem a singleton? (returns false if there can be multiple instances of this interface)
	virtual bool IsSingleton() { return true; }
};

class ICvar : public IAppSystem
{
public:
	// Allocate a unique DLL identifier
	virtual DWORD AllocateDLLIdentifier() = 0;

	// Register, unregister commands
	virtual void			RegisterConCommand(PVOID pCommandBase) = 0;
	virtual void			UnregisterConCommand(PVOID pCommandBase) = 0;
	virtual void			UnregisterConCommands(DWORD id) = 0;

	// If there is a +<varname> <value> on the command line, this returns the value.
	// Otherwise, it returns NULL.
	virtual const char* GetCommandLineValue(const char* pVariableName) = 0;

	// Try to find the cvar pointer by name
	virtual PVOID FindCommandBase(const char* name) = 0;
	virtual const PVOID FindCommandBase(const char* name) const = 0;
	virtual PVOID FindVar(const char* var_name) = 0;
	virtual const PVOID FindVar(const char* var_name) const = 0;
};

#endif // NEVELOSE_CSGO_MINI_H