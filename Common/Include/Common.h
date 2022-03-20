#pragma once

class CSSLCommon
{
public:
  static PSecurityFunctionTableW SSPI()
  {
    return g_pSSPI;
  }

protected:
  static PSecurityFunctionTableW g_pSSPI;

};