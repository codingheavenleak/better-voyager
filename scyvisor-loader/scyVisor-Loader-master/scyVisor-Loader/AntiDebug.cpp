#include "AntiDebug.h"

AntiDebug::AntiDebug() : DebuggerDetected(false) {}

void AntiDebug::checkIsDebuggerPresent() {
    if (IsDebuggerPresent()) {
        DebuggerDetected = true;
    }
}

void AntiDebug::checkRemoteDebugger() {
    BOOL isRemoteDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
    if (isRemoteDebuggerPresent) {
        DebuggerDetected = true;
    }
}

void AntiDebug::checkDebugRegisters() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            DebuggerDetected = true;
        }
    }
}

void AntiDebug::performTimingCheck() {
    auto start = std::chrono::high_resolution_clock::now();
    Sleep(10);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    if (duration.count() > 15) {
        DebuggerDetected = true;
    }
}

void AntiDebug::runChecks() {
    checkIsDebuggerPresent();
    checkRemoteDebugger();
    checkDebugRegisters();
    performTimingCheck();
}

bool AntiDebug::isDebuggerDetected() const {
    return DebuggerDetected;
}