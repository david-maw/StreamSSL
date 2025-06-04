#pragma once

#include <Windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <vector>

class SecBufferDescriptor {
public:
    // Constructor - creates descriptor with specified number of buffers
    explicit SecBufferDescriptor(ULONG bufferCount = 1);
    
    // Move constructor and assignment
    SecBufferDescriptor(SecBufferDescriptor&& other) noexcept;
    SecBufferDescriptor& operator=(SecBufferDescriptor&& other) noexcept;

    // Prevent copying as SecBufferDesc typically owns resources
    SecBufferDescriptor(const SecBufferDescriptor&) = delete;
    SecBufferDescriptor& operator=(const SecBufferDescriptor&) = delete;

    // Destructor
    ~SecBufferDescriptor();

    // Access methods
    SecBufferDesc* get() { return &m_desc; }
    const SecBufferDesc* get() const { return &m_desc; }
    SecBufferDesc* operator->() { return &m_desc; }
    const SecBufferDesc* operator->() const { return &m_desc; }

    // Buffer manipulation methods - does not take ownership of pvBuffer
    void SetBuffer(ULONG index, ULONG bufferType, ULONG cbBuffer, PVOID pvBuffer);
    
    // Reset all buffers to empty state without freeing memory
    void Clear();

    // Get individual buffer
    SecBuffer* GetBuffer(ULONG index);
    const SecBuffer* GetBuffer(ULONG index) const;

    // Get individual buffer
    SecBuffer* GetBufferByType(ULONG bufferType);
    const SecBuffer* GetBufferByType(ULONG bufferType) const;

    // Utility methods
    ULONG GetBufferCount() const { return m_desc.cBuffers; }
    bool IsEmpty() const;

private:
    SecBufferDesc m_desc;
    std::vector<SecBuffer> m_buffers;
};