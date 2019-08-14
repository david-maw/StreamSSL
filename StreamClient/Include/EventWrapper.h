#pragma once

class CEventWrapper
{
public:

	CEventWrapper(LPSECURITY_ATTRIBUTES lpEventAttributes = nullptr,
		BOOL bManualReset = TRUE,
		BOOL bInitialState = FALSE,
		LPCTSTR lpName = nullptr)
	{
		m_Event = CreateEvent(lpEventAttributes, bManualReset, bInitialState, lpName);
		if (!m_Event)
			throw "no event";
	}
	CEventWrapper(const CEventWrapper&) = delete;
	CEventWrapper& operator=(const CEventWrapper&) = delete;

	HANDLE Event() const
	{
		return m_Event;
	}

	operator const HANDLE() const
	{
		return m_Event;
	}

	~CEventWrapper()
	{
		if (m_Event)
		{
			CloseHandle(m_Event);
		}
	}

private:
	HANDLE
	m_Event{ nullptr };
};
