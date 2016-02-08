#pragma once
#include "stdafx.h"
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <wintrust.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")
#include "Handle.h"

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

// Traits for concrete handle types

struct ConstCertContextTraits : public HandleTraits<PCCERT_CONTEXT>
{
   static void Close(Type value)
   {
      CertFreeCertificateContext(value);
   }
};

class ConstCertContextHandle : public Handle<ConstCertContextTraits>
{
   friend Type & setref(ConstCertContextHandle & value) noexcept
   {
      _ASSERTE(!value);
      return *set(value);
   }
};


struct CertContextTraits : public HandleTraits<PCERT_CONTEXT>
{
   static void Close(Type value)
   {
      CertFreeCertificateContext(value);
   }
};

class CertContextHandle : public Handle<CertContextTraits>
{
};

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
