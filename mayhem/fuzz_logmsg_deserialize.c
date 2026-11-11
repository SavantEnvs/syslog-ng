/* Fuzzes the persisted LogMessage deserializer (disk-buffer / reliable queue format). */
#include "apphook.h"
#include "messages.h"
#include "cfg.h"
#include "logmsg/logmsg.h"
#include "logmsg/logmsg-serialize.h"
#include "serialize.h"
#include "scratch-buffers.h"

#include <stdint.h>
#include <stddef.h>

static void
drop_message(LogMessage *msg)
{
  log_msg_unref(msg);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  app_startup();
  msg_set_post_func(drop_message);
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 4)
    return -1;

  /* nv handles are serialized by name, so every input starts from a fresh registry */
  log_msg_registry_deinit();
  log_msg_registry_init();

  GString s = {0};
  s.allocated_len = 0;
  s.len = size;
  s.str = (gchar *) data;

  LogMessage *msg = log_msg_new_empty();
  SerializeArchive *sa = serialize_string_archive_new(&s);
  gboolean ok = log_msg_deserialize(msg, sa);
  serialize_archive_free(sa);
  log_msg_unref(msg);
  scratch_buffers_explicit_gc();
  return ok ? 0 : -1;
}
