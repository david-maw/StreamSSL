#pragma once

class CEventWrapper
{
public:

	CEventWrapper(LPSECURITY_ATTRIBUTES lpEventAttributes = nullptr,
		BOOL bManualReset = TRUE,
		BOOL bInitialState = FALSE,
		LPCTSTR lpName = nullptr)
		: m_Event(nullptr)
	{
		m_Event = CreateEvent(lpEventAttributes, bManualReset, bInitialState, lpName);
		if (!m_Event)
			throw "no event";
	}

	HANDLE Event() const
	{
		return m_Event;
	}

	operator const HANDLE()
	{
		return m_Event;
	}

	~CEventWrapper()
	{
		if (m_Event)
		{
			CloseHandle(m_Event);
			m_Event = nullptr;
		}
	}

private:
	HANDLE
		m_Event;
};