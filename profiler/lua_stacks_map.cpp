#include "lua_stacks_map.h"
#include <map>

void lua_stack_map::insert_lua_stack_map(const struct lua_stack_event *e)
{
    if (!e)
    {
        return;
    }
    auto it = map.find(e->user_stack_id);
    if (it == map.end())
    {
        lua_stack_backtrace stack = {*e};
        map[e->user_stack_id] = stack; // insert
        return;
    }
    lua_stack_backtrace *stack = &it->second;
    stack->push_back(*e);
    return;
}

// return the level of stack in the map
int lua_stack_map::get_lua_stack_backtrace(int user_stack_id, lua_stack_backtrace *stack)
{
    if (!stack)
    {
        return -1;
    }
    auto it = map.find(user_stack_id);
    if (it == map.end())
    {
        *stack = lua_stack_backtrace{};
        return -1;
    }
    *stack = it->second;
    return stack->size();
}