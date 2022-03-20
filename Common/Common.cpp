#include "pch.h"
#include "framework.h"

#include "Common.h"


// Global value to optimize access since it is set only once
PSecurityFunctionTable CSSLCommon::g_pSSPI = nullptr;

