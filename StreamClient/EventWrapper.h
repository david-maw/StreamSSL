#pragma once

class CEventWrapper
{
public:

	CEventWrapper(LPSECURITY_ATTRIBUTES lpEventAttributes = nullptr,
		BOOL bManualReset = TRUE,
		BOOL bInitialState = FALSE,
		LPCTSTR lpName = nullptr)
		: m_Event(NULL)
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
			m_Event = NULL;
		}
	}

private:
	HANDLE
		m_Event;
};