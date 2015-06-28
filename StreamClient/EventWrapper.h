#pragma once

class CEventWrapper
{
public:

	CEventWrapper(LPSECURITY_ATTRIBUTES lpEventAttributes = NULL,
					BOOL bManualReset = TRUE,
					BOOL bInitialState = FALSE,
					LPCTSTR lpName = NULL)
	: m_Event(NULL)
	{	
	    m_Event = CreateEvent(lpEventAttributes,bManualReset,bInitialState,lpName);
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

