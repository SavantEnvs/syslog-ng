/* Fuzzes the RFC3164/RFC5424 syslog line parser (syslog_format_handler). Byte 0..2 select
 * the parse flags; the rest is the raw message. */
#include "apphook.h"
#include "messages.h"
#include "cfg.h"
#include "msg-format.h"
#include "syslog-format.h"
#include "logmsg/logmsg.h"
#include "scratch-buffers.h"

#include <stdint.h>
#include <string.h>
#include <stddef.h>

static GlobalConfig *cfg;

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
  syslog_format_init();
  cfg = cfg_new_snippet();
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 3)
    return -1;

  static const guint32 selectable[] =
  {
    LP_CHECK_HOSTNAME, LP_SYSLOG_PROTOCOL, LP_ASSUME_UTF8, LP_VALIDATE_UTF8, LP_SANITIZE_UTF8,
    LP_NO_MULTI_LINE, LP_STORE_LEGACY_MSGHDR, LP_EXPECT_HOSTNAME, LP_NO_PARSE_DATE,
    LP_STORE_RAW_MESSAGE, LP_GUESS_TIMEZONE, LP_NO_HEADER, LP_NO_RFC3164_FALLBACK,
    LP_CHECK_PROGRAM, LP_NO_PARSE_PROGRAM, LP_PIGGYBACK_ERRORS,
  };
  guint32 sel = data[0] | ((guint32) data[1] << 8);
  guint32 flags = 0;
  for (size_t i = 0; i < sizeof(selectable) / sizeof(selectable[0]); i++)
    if (sel & (1u << i))
      flags |= selectable[i];

  MsgFormatOptions options;
  memset(&options, 0, sizeof(options));
  msg_format_options_defaults(&options);
  options.flags = flags;
  msg_format_options_init(&options, cfg);

  LogMessage *msg = log_msg_new_empty();
  gsize problem_position = 0;
  syslog_format_handler(&options, msg, data + 2, size - 2, &problem_position);

  log_msg_unref(msg);
  msg_format_options_destroy(&options);
  scratch_buffers_explicit_gc();
  return 0;
}
