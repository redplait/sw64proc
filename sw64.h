#pragma once
//------------------------------------------------------------------
DECLARE_PROC_LISTENER(idb_listener_t, struct sw64_t);

struct sw64_t : public procmod_t
{
  netnode helper;
  idb_listener_t idb_listener = idb_listener_t(*this);
#define USE_GOT 1
  ushort idpflags = 0;

  inline bool use_got() const
  {
    return (idpflags & USE_GOT);
  }

  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded);
  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
};