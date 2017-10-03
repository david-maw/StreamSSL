#include "stdafx.h"
#include "SecurityHandle.h"
#include "SSLClient.h"

void CredentialHandle::Close() noexcept
{
   if (*this)
   {
      CSSLClient::g_pSSPI->FreeCredentialsHandle(&m_value);
   }
}

void SecurityContextHandle::Close() noexcept
{
   if (*this)
   {
      CSSLClient::g_pSSPI->DeleteSecurityContext(&m_value);
   }
}