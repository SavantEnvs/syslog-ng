/* Known-answer probe for mayhem/test.sh: parses fixed inputs through the real syslog-ng library
 * and prints the results, so test.sh can compare them against the expected values. */
#include "apphook.h"
#include "cfg.h"
#include "messages.h"
#include "msg-format.h"
#include "syslog-format.h"
#include "logmsg/logmsg.h"
#include "logmsg/logmsg-serialize.h"
#include "serialize.h"
#include "radix.h"
#include "transport/logtransport.h"
#include "logproto/logproto-server.h"
#include "logproto/logproto-framed-server.h"
#include "scratch-buffers.h"

#include <stdio.h>
#include <string.h>

static void
drop_message(LogMessage *msg)
{
  log_msg_unref(msg);
}

static void
print_value(LogMessage *msg, const char *label, NVHandle handle)
{
  gssize len;
  const gchar *v = log_msg_get_value(msg, handle, &len);
  printf("%s=%.*s\n", label, (int) len, v);
}

typedef struct
{
  LogTransport super;
  const char *data;
  gsize len, pos;
} MemTransport;

static gssize
mem_read(LogTransport *s, gpointer buf, gsize count, LogTransportAuxData *aux)
{
  MemTransport *self = (MemTransport *) s;
  gsize n = MIN(count, self->len - self->pos);
  memcpy(buf, self->data + self->pos, n);
  self->pos += n;
  return n;
}

int
main(void)
{
  app_startup();
  msg_set_post_func(drop_message);
  syslog_format_init();
  GlobalConfig *cfg = cfg_new_snippet();

  MsgFormatOptions options;
  memset(&options, 0, sizeof(options));
  msg_format_options_defaults(&options);
  options.flags |= LP_SYSLOG_PROTOCOL;
  msg_format_options_init(&options, cfg);

  const char *raw =
    "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
    "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] An application event log entry";
  LogMessage *msg = log_msg_new_empty();
  gsize problem = 0;
  printf("parse_ok=%d\n", syslog_format_handler(&options, msg, (const guchar *) raw, strlen(raw), &problem));
  printf("pri=%d\n", msg->pri);
  print_value(msg, "host", LM_V_HOST);
  print_value(msg, "program", LM_V_PROGRAM);
  print_value(msg, "msgid", log_msg_get_value_handle("MSGID"));
  print_value(msg, "sd_iut", log_msg_get_value_handle(".SDATA.exampleSDID@32473.iut"));
  print_value(msg, "message", LM_V_MESSAGE);

  GString *buf = g_string_new(NULL);
  SerializeArchive *sa = serialize_string_archive_new(buf);
  log_msg_serialize(msg, sa, 0);
  serialize_archive_free(sa);
  log_msg_unref(msg);

  log_msg_registry_deinit();
  log_msg_registry_init();
  LogMessage *msg2 = log_msg_new_empty();
  sa = serialize_string_archive_new(buf);
  printf("deserialize_ok=%d\n", log_msg_deserialize(msg2, sa));
  serialize_archive_free(sa);
  printf("pri2=%d\n", msg2->pri);
  print_value(msg2, "host2", LM_V_HOST);
  print_value(msg2, "sd_event2", log_msg_get_value_handle(".SDATA.exampleSDID@32473.eventSource"));
  print_value(msg2, "message2", LM_V_MESSAGE);
  log_msg_unref(msg2);
  g_string_free(buf, TRUE);

  RNode *root = r_new_node("", NULL);
  gchar *pattern = g_strdup("user @ESTRING:user: @from @IPv4:ip@ port @NUMBER:port@");
  r_insert_node(root, pattern, (gpointer) "rule1", NULL, NULL, NULL);
  g_free(pattern);
  GArray *matches = g_array_new(FALSE, TRUE, sizeof(RParserMatch));
  g_array_set_size(matches, 1);
  gchar *key = g_strdup("user alice from 10.1.2.3 port 2222");
  RNode *found = r_find_node(root, key, strlen(key), matches);
  printf("radix=%s\n", found ? (const char *) found->value : "(none)");
  for (guint i = 1; i < matches->len; i++)
    {
      RParserMatch *m = &g_array_index(matches, RParserMatch, i);
      printf("radix_%s=%.*s\n", log_msg_get_value_name(m->handle, NULL), m->len, key + m->ofs);
    }
  g_array_free(matches, TRUE);
  g_free(key);
  r_free_node(root, NULL);

  LogProtoServerOptionsStorage popts;
  memset(&popts, 0, sizeof(popts));
  log_proto_server_options_defaults(&popts);
  log_proto_server_options_init(&popts, cfg);
  MemTransport *t = g_new0(MemTransport, 1);
  log_transport_init_instance(&t->super, "mem", -1);
  t->super.read = mem_read;
  t->data = "5 hello11 world!!!!!!";
  t->len = strlen(t->data);
  LogProtoServer *proto = log_proto_framed_server_new(&t->super, &popts);
  for (int i = 0; i < 3; i++)
    {
      const guchar *m = NULL;
      gsize mlen = 0;
      gboolean may_read = TRUE;
      Bookmark bm;
      LogTransportAuxData aux;
      log_transport_aux_data_init(&aux);
      LogProtoStatus st = log_proto_server_fetch(proto, &m, &mlen, &may_read, &aux, &bm);
      log_transport_aux_data_destroy(&aux);
      if (m)
        printf("frame%d=%.*s\n", i, (int) mlen, m);
      else
        printf("frame%d_status=%d\n", i, st);
    }
  log_proto_server_free(proto);
  log_proto_server_options_destroy(&popts);

  msg_format_options_destroy(&options);
  scratch_buffers_explicit_gc();
  return 0;
}
