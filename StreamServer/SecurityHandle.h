#pragma once
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <wintrust.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")
#include "Handle.h"

/*
This is one of 2 different approaches to handling old Windows handle classes.

The approach in "SecurityHandle.h" encapsulates the native handles but leaves the class usage 
somewhat untouched (certainly not quite untouched, since handle usages tend to be replaced by 
"get" or "set" calls, but generally the notion of a handle to an object is preserved with lifetime 
management using RAII added.

The approach in "CertRAII...." also replaces handles with objects encapsulating the handles, but 
these behave as if they were the underlying object. So, for example instead of a "CertContextHandle"
class, we have a "Cert" class with a Cert::SetCertificateContextProperty method, which ultimately
calls ::CertSetCertificateContextProperty. This works fine if only a relatively small number
of methods are to be called, but since each one has to be added to the class, it can be a pain
if there are a lot of methods. 
*/

class CredentialHandle
{
public:

   CredentialHandle() noexcept = default;
   CredentialHandle(CredentialHandle const &) = delete;
   CredentialHandle & operator=(CredentialHandle const &) = delete;

   CredentialHandle(CredHandle value) noexcept :
   m_value(value)
   {}

   CredentialHandle(CredentialHandle && other) noexcept :
      m_value(detach(other))
   {}

   CredentialHandle & operator=(CredentialHandle && other) noexcept
   {
      if (this != &other)
      {
         attach(*this, detach(other));
      }

      return *this;
   }

   ~CredentialHandle() noexcept
   {
      Close();
   }

   void Close() noexcept;

   constexpr static CredHandle Invalid() noexcept
   {
      return{ (ULONG_PTR)((INT_PTR)-1), (ULONG_PTR)((INT_PTR)-1) };
   }

   explicit operator bool() const noexcept
   {
      return SecIsValidHandle(&m_value);
   }

   friend CredHandle get(CredentialHandle const & CredentialHandle) noexcept
   {
      return CredentialHandle.m_value;
   }

   friend CredHandle * set(CredentialHandle & CredentialHandle) noexcept
   {
      _ASSERTE(!CredentialHandle);
      return &CredentialHandle.m_value;
   }

   friend void attach(CredentialHandle & CredentialHandle, CredHandle value) noexcept
   {
      CredentialHandle.Close();
      CredentialHandle.m_value = value;
   }

   friend CredHandle detach(CredentialHandle & CredentialHandle) noexcept
   {
      CredHandle value = CredentialHandle.m_value;
      CredentialHandle.m_value = Invalid();
      return value;
   }

   friend void swap(CredentialHandle & left, CredentialHandle & right) noexcept
   {
      CredHandle temp = left.m_value;
      left.m_value = right.m_value;
      right.m_value = temp;
   }

   friend bool operator==(CredentialHandle const & left, CredentialHandle const & right) noexcept
   {
      return get(left).dwLower == get(right).dwLower && get(left).dwUpper == get(right).dwUpper;
   }

   friend bool operator!=(CredentialHandle const & left, CredentialHandle const & right) noexcept
   {
      return !(left == right);
   }

private:

   CredHandle m_value = Invalid();

};

// Concrete handle types for certificates (traits first, then the actual class, defined using the traits class)

struct CertContextTraits : public HandleTraits<PCCERT_CONTEXT>
{
   static void Close(Type value)
   {
      CertFreeCertificateContext(value);
   }
};

class ConstCertContextHandle : public Handle<CertContextTraits>
{
   friend Type & setref(ConstCertContextHandle & value) noexcept
   {
      _ASSERTE(!value);
      return *set(value);
   }
};

class CertContextHandle : public Handle<CertContextTraits>
{
};

// SecurityContextHandle class

class SecurityContextHandle
{
public:

   SecurityContextHandle() noexcept = default;
   SecurityContextHandle(SecurityContextHandle const &) = delete;
   SecurityContextHandle & operator=(SecurityContextHandle const &) = delete;

   SecurityContextHandle(CtxtHandle value) noexcept :
   m_value(value)
   {}

   SecurityContextHandle(SecurityContextHandle && other) noexcept :
      m_value(detach(other))
   {}

   SecurityContextHandle & operator=(SecurityContextHandle && other) noexcept
   {
      if (this != &other)
      {
         attach(*this, detach(other));
      }

      return *this;
   }

   ~SecurityContextHandle() noexcept
   {
      Close();
   }

   void Close() noexcept;

   constexpr static CtxtHandle Invalid() noexcept
   {
      return{ (ULONG_PTR)((INT_PTR)-1), (ULONG_PTR)((INT_PTR)-1) };
   }

   explicit operator bool() const noexcept
   {
      return SecIsValidHandle(&m_value);
   }

   friend CtxtHandle get(SecurityContextHandle const & SecurityContextHandle) noexcept
   {
      return SecurityContextHandle.m_value;
   }

   friend CtxtHandle * set(SecurityContextHandle & SecurityContextHandle) noexcept
   {
      _ASSERTE(!SecurityContextHandle);
      return &SecurityContextHandle.m_value;
   }

   friend void attach(SecurityContextHandle & SecurityContextHandle, CtxtHandle value) noexcept
   {
      SecurityContextHandle.Close();
      SecurityContextHandle.m_value = value;
   }

   friend CtxtHandle detach(SecurityContextHandle & SecurityContextHandle) noexcept
   {
      CtxtHandle value = SecurityContextHandle.m_value;
      SecurityContextHandle.m_value = Invalid();
      return value;
   }

   friend void swap(SecurityContextHandle & left, SecurityContextHandle & right) noexcept
   {
      CtxtHandle temp = left.m_value;
      left.m_value = right.m_value;
      right.m_value = temp;
   }

   friend bool operator==(SecurityContextHandle const & left, SecurityContextHandle const & right) noexcept
   {
      return get(left).dwLower == get(right).dwLower && get(left).dwUpper == get(right).dwUpper;
   }

   friend bool operator!=(SecurityContextHandle const & left, SecurityContextHandle const & right) noexcept
   {
      return !(left == right);
   }


private:

   CtxtHandle m_value = Invalid();

};
