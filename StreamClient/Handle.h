#pragma once
// Based on Kenny Kerr's handle class from 2011 - https://msdn.microsoft.com/%20magazine/hh288076

//template <typename Type, typename Traits>
//class unique_handle
//{
//	unique_handle(unique_handle const &);
//	unique_handle & operator=(unique_handle const &);
//	void close() throw()
//	{
//		if (*this)
//		{
//			Traits::close(m_value);
//		}
//	}
//	Type m_value;
//public:
//	explicit unique_handle(Type value = Traits::invalid()) throw() :
//	m_value(value)
//	{
//	}
//	~unique_handle() throw()
//	{
//		close();
//	}
//private:
//	struct boolean_struct { int member; };
//	typedef int boolean_struct::* boolean_type;
//	bool operator==(unique_handle const &);
//	bool operator!=(unique_handle const &);
//public:
//	operator boolean_type() const throw()
//	{
//		return Traits::invalid() != m_value ? &boolean_struct::member : nullptr;
//	}
//	Type get() const throw()
//	{
//		return m_value;
//	}
//	bool reset(Type value = Traits::invalid()) throw()
//	{
//		if (m_value != value)
//		{
//			close();
//			m_value = value;
//		}
//		return *this;
//	}
//	Type release() throw()
//	{
//		auto value = m_value;
//		m_value = Traits::invalid();
//		return value;
//	}
//	unique_handle(unique_handle && other) throw() :
//		m_value(other.release())
//	{
//	}
//	unique_handle & operator=(unique_handle && other) throw()
//	{
//		reset(other.release());
//		return *this;
//	}
//	Type & getRef() throw()
//	{
//		return m_value;
//	}
//};
//
//// Traits for concrete handle types
//
//
//struct HandleTraits
//{
//	static HANDLE invalid() throw() 
//	{
//		return nullptr;
//	}
//
//	static void close(HANDLE value) throw()
//	{
//		CloseHandle(value);
//	}
//};
//
//struct CertContextTraits
//{
//	static PCCERT_CONTEXT invalid() throw() 
//	{
//		return nullptr;
//	}
//
//	static void close(PCCERT_CONTEXT value)
//	{
//		CertFreeCertificateContext(value);
//	}
//};
//
//class ConstCertContextHandle : public unique_handle<PCCERT_CONTEXT, CertContextTraits>
//{
//};
//
//struct CredHandleTraits
//{
//	static CredHandle invalid() throw() 
//	{
//		return *(new SecHandle());
//	}
//
//	static void close(CredHandle value)
//	{
////		CSSLClient::g_pSSPI->FreeCredentialsHandle(&value);
//	}
//};
//
//class CredentialHandle : public unique_handle<CredHandle, CredHandleTraits>
//{
//};


template <typename T>
struct HandleTraits
{
   using Type = T;

   constexpr static Type Invalid() noexcept
   {
      return nullptr;
   }

   // static void Close(Type value) noexcept;
};


template <typename T>
class Handle
{
public:

   using Type = typename T::Type;

   Handle() noexcept = default;
   Handle(Handle const &) = delete;
   Handle & operator=(Handle const &) = delete;

   Handle(Type value) noexcept :
   m_value(value)
   {}

   Handle(Handle && other) noexcept :
      m_value(detach(other))
   {}

   Handle & operator=(Handle && other) noexcept
   {
      if (this != &other)
      {
         attach(*this, detach(other));
      }

      return *this;
   }

   ~Handle() noexcept
   {
      Close();
   }

   void Close() noexcept
   {
      if (*this)
      {
         T::Close(m_value);
      }
   }

   explicit operator bool() const noexcept
   {
      return m_value != T::Invalid();
   }

   friend Type get(Handle const & handle) noexcept
   {
      return handle.m_value;
   }

   friend Type * set(Handle & handle) noexcept
   {
      _ASSERTE(!handle);
      return &handle.m_value;
   }

   friend void attach(Handle & handle, Type value) noexcept
   {
      handle.Close();
      handle.m_value = value;
   }

   friend Type detach(Handle & handle) noexcept
   {
      Type value = handle.m_value;
      handle.m_value = T::Invalid();
      return value;
   }

   friend void swap(Handle & left, Handle & right) noexcept
   {
      Type temp = left.m_value;
      left.m_value = right.m_value;
      right.m_value = temp;
   }

private:

   Type m_value = T::Invalid();

};

template <typename T>
bool operator==(Handle<T> const & left, Handle<T> const & right) noexcept
{
   return get(left) == get(right);
}

template <typename T>
bool operator!=(Handle<T> const & left, Handle<T> const & right) noexcept
{
   return !(left == right);
}

template <typename T>
bool operator<(Handle<T> const & left, Handle<T> const & right) noexcept
{
   return get(left) < get(right);
}

template <typename T>
bool operator>(Handle<T> const & left, Handle<T> const & right) noexcept
{
   return right < left;
}

template <typename T>
bool operator<=(Handle<T> const & left, Handle<T> const & right) noexcept
{
   return !(right < left);
}

template <typename T>
bool operator>=(Handle<T> const & left, Handle<T> const & right) noexcept
{
   return !(left < right);
}


   //struct CredHandleTraits
   //{
   //   using Type = CredHandle;

   //   constexpr static Type Invalid() noexcept
   //   {
   //      return { (ULONG_PTR)((INT_PTR)-1), (ULONG_PTR)((INT_PTR)-1) };
   //   }

   //   static void close(Type value) noexcept
   //   {
   //      //		CSSLClient::g_pSSPI->FreeCredentialsHandle(&value);
   //   }
   //};

   /*class CredentialHandle : public Handle<CredHandleTraits>
   {
   public:
      explicit operator bool() const noexcept
      {
         return false;
      }
   };*/

 