#pragma once
// Based on Kenny Kerr's handle class from 2011 - https://msdn.microsoft.com/%20magazine/hh288076

#include <WinCrypt.h>
#include "SSLClient.h"

template <typename Type, typename Traits>
class unique_handle
{
	unique_handle(unique_handle const &);
	unique_handle & operator=(unique_handle const &);
	void close() throw()
	{
		if (*this)
		{
			Traits::close(m_value);
		}
	}
	Type m_value;
public:
	explicit unique_handle(Type value = Traits::invalid()) throw() :
	m_value(value)
	{
	}
	~unique_handle() throw()
	{
		close();
	}
private:
	struct boolean_struct { int member; };
	typedef int boolean_struct::* boolean_type;
	bool operator==(unique_handle const &);
	bool operator!=(unique_handle const &);
public:
	operator boolean_type() const throw()
	{
		return Traits::invalid() != m_value ? &boolean_struct::member : nullptr;
	}
	Type get() const throw()
	{
		return m_value;
	}
	bool reset(Type value = Traits::invalid()) throw()
	{
		if (m_value != value)
		{
			close();
			m_value = value;
		}
		return *this;
	}
	Type release() throw()
	{
		auto value = m_value;
		m_value = Traits::invalid();
		return value;
	}
	unique_handle(unique_handle && other) throw() :
		m_value(other.release())
	{
	}
	unique_handle & operator=(unique_handle && other) throw()
	{
		reset(other.release());
		return *this;
	}
	Type & getRef() throw()
	{
		return m_value;
	}
};

// Traits for concrete handle types


struct HandleTraits
{
	static HANDLE invalid() throw() 
	{
		return nullptr;
	}

	static void close(HANDLE value) throw()
	{
		CloseHandle(value);
	}
};

struct CertContextTraits
{
	static PCCERT_CONTEXT invalid() throw() 
	{
		return nullptr;
	}

	static void close(PCCERT_CONTEXT value)
	{
		CertFreeCertificateContext(value);
	}
};

class CertContextHandle : public unique_handle<PCCERT_CONTEXT, CertContextTraits>
{
};

struct CredHandleTraits
{
	static CredHandle invalid() throw() 
	{
		return *(new SecHandle());
	}

	static void close(CredHandle value)
	{
		CSSLClient::g_pSSPI->FreeCredentialsHandle(&value);
	}
};

class CredentialHandle : public unique_handle<CredHandle, CredHandleTraits>
{
};




//
//
//template <typename T>
//struct HandleTraits
//{
//public:
//	typedef T HandleType;
//  static HandleType Invalid() 
//  {
//    return nullptr;
//  }
//  // Static void Close(Type value);
//};
//
//   template <typename T>
//   class Handle
//   {
//   public:
//
//      //typedef  HandleType T::HandleType;
//
//      //Handle() = default;
//	private:
//		Handle(Handle const &);
//      Handle & operator=(Handle const &);
//	public:
//      Handle(T::HandleType value) :
//      m_value(value)
//      {}
//
//      Handle(Handle && other) :
//         m_value(detach(other))
//      {}
//
//      Handle & operator=(Handle && other)
//      {
//         if (this != &other)
//         {
//            attach(*this, detach(other));
//         }
//
//         return *this;
//      }
//
//      ~Handle()
//      {
//         Close();
//      }
//
//      void Close()
//      {
//         if (*this)
//         {
//            T::Close(m_value);
//         }
//      }
//
//      explicit operator bool() const
//      {
//         return m_value != T::Invalid();
//      }
//
//      friend Type get(Handle const & handle)
//      {
//         return handle.m_value;
//      }
//
//      friend Type * set(Handle & handle)
//      {
//         MODERN_ASSERT(!handle);
//         return &handle.m_value;
//      }
//
//      friend void attach(Handle & handle, Type value)
//      {
//         handle.Close();
//         handle.m_value = value;
//      }
//
//      friend Type detach(Handle & handle)
//      {
//         Type value = handle.m_value;
//         handle.m_value = T::Invalid();
//         return value;
//      }
//
//      friend void swap(Handle & left, Handle & right)
//      {
//         Type temp = left.m_value;
//         left.m_value = right.m_value;
//         right.m_value = temp;
//      }
//
//   private:
//
//      Type m_value = T::Invalid();
//
//   };
//
//   template <typename T>
//   bool operator==(Handle<T> const & left, Handle<T> const & right)
//   {
//      return get(left) == get(right);
//   }
//
//   template <typename T>
//   bool operator!=(Handle<T> const & left, Handle<T> const & right) 
//   {
//      return !(left == right);
//   }
//
//   template <typename T>
//   bool operator<(Handle<T> const & left, Handle<T> const & right) 
//   {
//      return get(left) < get(right);
//   }
//
//   template <typename T>
//   bool operator>(Handle<T> const & left, Handle<T> const & right) 
//   {
//      return right < left;
//   }
//
//   template <typename T>
//   bool operator<=(Handle<T> const & left, Handle<T> const & right) 
//   {
//      return !(right < left);
//   }
//
//   template <typename T>
//   bool operator>=(Handle<T> const & left, Handle<T> const & right) 
//   {
//      return !(left < right);
//   }
//
//   // Traits for concrete handle types
//
//   struct CertContextTraits : HandleTraits<PCCERT_CONTEXT>
//   {
//      static void Close(T::T value)
//      {
//         CertFreeCertificateContext(value);
//      }
//   };
//
//   // Concrete handle types
//
//   class CertContextHandle : public Handle<CertContextTraits>
//   {
//   };
