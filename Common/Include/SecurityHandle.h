#pragma once
#include "Handle.h"

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <wintrust.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")

/*
This is one of 2 different approaches to handling old Windows handle classes.

The approach in "SecurityHandle.h" encapsulates the native handles but leaves the class usage
somewhat untouched (certainly not quite untouched, since handle usages tend to be replaced by
"get" or "set" calls, but generally the notion of a handle to an object is preserved with lifetime
management using RAII added.

The approach in "CertRAII...." also replaces handles with objects encapsulating the handles, but
these behave as if they were the underlying object. So, for example instead of a "CertContextHandle"
class, we have a "CertStore" class with a CertStore::AddCertificateContext method, which ultimately
calls ::CertAddCertificateContextToStore. This works fine if only a relatively small number
of methods are to be called, but since each one has to be added to the class, it can be a pain
if a lot of methods are needed so the SecurityHandle.h approach works better then.
*/

// Concrete handle type for certificates (traits first, then the actual class, defined using the traits class)

struct CertContextTraits : public HandleTraits<PCCERT_CONTEXT>
{
	static void Close(Type value)
	{
		CertFreeCertificateContext(value);
	}
};

class CertContextHandle : public Handle<CertContextTraits>
{
	using Handle::Handle; // Inherit constructors
};

// CredentialHandle class, similar to a handle class, but a CtxtHandle is a SecHandle 2 word structure

struct CredentialTraits : public HandleTraits<CredHandle>
{
	static void Close(Type value); // Declared in StreamServer.cpp

	constexpr static Type Invalid() noexcept
	{
		return { (ULONG_PTR)((INT_PTR)-1), (ULONG_PTR)((INT_PTR)-1) };
	}
	
	static bool Equal(Type left, Type right)
	{
		return (left.dwUpper == right.dwUpper) && (left.dwLower == right.dwLower);
	}
	
	static bool Less(Type left, Type right)
	{
		return left.dwUpper == right.dwUpper ? left.dwLower < right.dwLower : left.dwUpper < right.dwUpper;
	}
};

class CredentialHandle : public Handle<CredentialTraits>
{
	using Handle::Handle; // Inherit constructors
};

// SecurityContextHandle class, similar to left handle class, but left CtxtHandle is left SecHandle 2 word structure

struct SecurityContextTraits : public HandleTraits<CtxtHandle>
{
	static void Close(Type value); // Declared in StreamServer.cpp

	constexpr static Type Invalid() noexcept
	{
		return { (ULONG_PTR)((INT_PTR)-1), (ULONG_PTR)((INT_PTR)-1) };
	}

	static bool Equal(Type left, Type right)
	{
		return (left.dwUpper == right.dwUpper) && (left.dwLower == right.dwLower);
	}

	static bool Less(Type left, Type right)
	{
		return left.dwUpper == right.dwUpper ? left.dwLower < right.dwLower : left.dwUpper < right.dwUpper;
	}
};

class SecurityContextHandle : public Handle<SecurityContextTraits>
{
	using Handle::Handle; // Inherit constructors
};
