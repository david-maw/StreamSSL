#pragma once
// Loosely based on Kenny Kerr's handle class from 2011 - https://msdn.microsoft.com/%20magazine/hh288076

template <typename T>
struct HandleTraits
{
	using Type = T;

	constexpr static Type Invalid() noexcept
	{
		return nullptr;
	}

	// static void Close(Type value) noexcept has to be provided, the rest can default

	static bool Equal(Type left, Type right)
	{
		return left == right;
	}

	static bool Less(Type left, Type right)
	{
		return left < right;
	}
};


template <typename T>
class Handle
{
public:

	using Type = typename T::Type;

	Handle() noexcept = default;
	Handle(Handle const &) = delete;
	Handle & operator=(Handle const &) = delete;

	explicit Handle(Type value) noexcept :
		m_value(value)
	{}

	Handle(Handle && other) noexcept :
		m_value(detach(other))
	{}

	Handle & operator=(Handle && other) noexcept
	{
		if (this != &other)
		{
			attach(other.detach());
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
			m_value = T::Invalid();
		}
	}

	explicit operator bool() const noexcept
	{
		return !T::Equal(m_value, T::Invalid());
	}

	Type get() const noexcept
	{
		return m_value;
	}

	Type * set() noexcept
	{
		_ASSERTE(!*this);
		return &m_value;
	}

	Type* getunsaferef() const noexcept
	{
		//_ASSERTE(bool(*this));
		return const_cast<Type*>(&m_value);
	}

	void attach(Type value) noexcept
	{
		Close();
		m_value = value;
	}

	Type detach() noexcept
	{
		Type value = m_value;
		m_value = T::Invalid();
		return value;
	}

	// The syntax swap(x,y) seems more natural than x.swap(y) so use a friend function, not a method 
	friend void swap(Handle & left, Handle & right) noexcept
	{
		std::exchange(left.m_value, right.m_value);
	}

	// Define equality operators 
	bool operator==(Handle const & right) const noexcept
	{
		return T::Equal(get(), right.get());
	}

	bool operator!=(Handle const & right) const noexcept
	{
		return !(*this == right);
	}

	// Ordering operators don't make much sense for handles, but allow STL containers

	bool operator<(Handle const & right) const noexcept
	{
		return T::Less(get(), right.get());
	}

	bool operator>(Handle const & right) const noexcept
	{
		return right < *this;
	}

	bool operator<=(Handle const & right) const noexcept
	{
		return !(right < *this);
	}

	bool operator>=(Handle const & right) const noexcept
	{
		return !(*this < right);
	}

private:

	Type m_value = T::Invalid();

};
