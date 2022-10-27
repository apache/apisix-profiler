#ifndef LUA_STACKS_HELPER_H
#define LUA_STACKS_HELPER_H

#define MAX_STACK_DEPTH 64

#include "profile.h"
#include <map>
#include <vector>

// lua stack backtrace events
using lua_stack_backtrace = std::vector<struct lua_stack_event>;

// The map to collect and reserved the stack event found in perf event.
// The stack info will be printed when the profiler stopped.
class lua_stack_map
{
private:
    std::map<int, lua_stack_backtrace> map;

public:
    // insert a lua stack event into the map.
    // The event will be push into the backtrace vector with the same stack_id.
    void insert_lua_stack_map(const struct lua_stack_event *event);
    // get the lua stack backtrace with the stack_id.
    // return the level of stack in the map
    int get_lua_stack_backtrace(int user_stack_id, lua_stack_backtrace *stack);
};

#endif