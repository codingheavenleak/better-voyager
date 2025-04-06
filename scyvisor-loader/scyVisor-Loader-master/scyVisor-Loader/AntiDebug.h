#pragma once

#include <Windows.h>
#include <chrono>
#include <thread>

class AntiDebug {
private:
    volatile bool DebuggerDetected;

    void checkIsDebuggerPresent();
    void checkRemoteDebugger();
    void checkDebugRegisters();
    void performTimingCheck();

public:
    AntiDebug();
    void runChecks();
    bool isDebuggerDetected() const;
};