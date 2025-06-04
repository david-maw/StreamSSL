#include "pch.h"
#include "SecBufferDescriptor.h"
#include <stdexcept>

SecBufferDescriptor::SecBufferDescriptor(ULONG bufferCount)
    : m_buffers(bufferCount)
{
    m_desc.ulVersion = SECBUFFER_VERSION;
    m_desc.cBuffers = bufferCount;
    m_desc.pBuffers = m_buffers.data();

    // Initialize all buffers to empty
    Clear();
}

SecBufferDescriptor::SecBufferDescriptor(SecBufferDescriptor&& other) noexcept
    : m_desc(other.m_desc)
    , m_buffers(std::move(other.m_buffers))
{
    // Update the buffer pointer to point to our moved buffer array
    m_desc.pBuffers = m_buffers.data();
    
    // Clear the source descriptor
    other.m_desc.cBuffers = 0;
    other.m_desc.pBuffers = nullptr;
}

SecBufferDescriptor& SecBufferDescriptor::operator=(SecBufferDescriptor&& other) noexcept
{
    if (this != &other)
    {
        m_desc = other.m_desc;
        m_buffers = std::move(other.m_buffers);
        
        // Update the buffer pointer to point to our moved buffer array
        m_desc.pBuffers = m_buffers.data();
        
        // Clear the source descriptor
        other.m_desc.cBuffers = 0;
        other.m_desc.pBuffers = nullptr;
    }
    return *this;
}

SecBufferDescriptor::~SecBufferDescriptor()
{
    Clear();
}

void SecBufferDescriptor::SetBuffer(ULONG index, ULONG bufferType, ULONG cbBuffer, PVOID pvBuffer)
{
    if (index >= m_desc.cBuffers)
        throw std::out_of_range("Buffer index out of range");

    m_buffers[index].BufferType = bufferType;
    m_buffers[index].cbBuffer = cbBuffer;
    m_buffers[index].pvBuffer = pvBuffer;
}

void SecBufferDescriptor::Clear()
{
    for (ULONG i = 0; i < m_desc.cBuffers; i++)
    {
        // Reset to empty state without freeing memory
        m_buffers[i].BufferType = SECBUFFER_EMPTY;
        m_buffers[i].cbBuffer = 0;
        m_buffers[i].pvBuffer = nullptr;
    }
}

SecBuffer* SecBufferDescriptor::GetBuffer(ULONG index)
{
    if (index >= m_desc.cBuffers)
        throw std::out_of_range("Buffer index out of range");
    
    return &m_buffers[index];
}

const SecBuffer* SecBufferDescriptor::GetBuffer(ULONG index) const
{
    if (index >= m_desc.cBuffers)
        throw std::out_of_range("Buffer index out of range");
    
    return &m_buffers[index];
}

SecBuffer* SecBufferDescriptor::GetBufferByType(ULONG bufferType)
{
    for (ULONG i = 0; i < m_desc.cBuffers; i++)
    {
        if (m_buffers[i].BufferType == bufferType)
            return &m_buffers[i];
    }
    return nullptr;
}

const SecBuffer* SecBufferDescriptor::GetBufferByType(ULONG bufferType) const
{
    for (ULONG i = 0; i < m_desc.cBuffers; i++)
    {
        if (m_buffers[i].BufferType == bufferType)
            return &m_buffers[i];
    }
    return nullptr;
}

bool SecBufferDescriptor::IsEmpty() const
{
    for (ULONG i = 0; i < m_desc.cBuffers; i++)
    {
        if (m_buffers[i].BufferType != SECBUFFER_EMPTY)
            return false;
    }
    return true;
}