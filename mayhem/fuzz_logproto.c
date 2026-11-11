/* Fuzzes the syslog-ng input framing protocols (framed, text, dgram, auto, binary/padded record)
 * over an in-memory transport. Byte 0 selects the protocol, byte 1 the message-size limit,
 * byte 2 the record size / read chunking; the rest is the byte stream. */
#include "apphook.h"
#include "messages.h"
#include "cfg.h"
#include "logmsg/logmsg.h"
#include "transport/logtransport.h"
#include "transport/transport-aux-data.h"
#include "logproto/logproto-server.h"
#include "logproto/logproto-framed-server.h"
#include "logproto/logproto-text-server.h"
#include "logproto/logproto-dgram-server.h"
#include "logproto/logproto-auto-server.h"
#include "logproto/logproto-record-server.h"
#include "scratch-buffers.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct
{
  LogTransport super;
  const guchar *data;
  gsize len;
  gsize pos;
  gsize chunk;
} MemTransport;

static gssize
mem_transport_read(LogTransport *s, gpointer buf, gsize count, LogTransportAuxData *aux)
{
  MemTransport *self = (MemTransport *) s;
  gsize n = self->len - self->pos;
  if (n > count)
    n = count;
  if (n > self->chunk)
    n = self->chunk;
  memcpy(buf, self->data + self->pos, n);
  self->pos += n;
  return n;
}

static gssize
mem_transport_write(LogTransport *s, const gpointer buf, gsize count)
{
  return count;
}

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
  cfg = cfg_new_snippet();
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 3)
    return -1;

  guint proto_sel = data[0] % 6;
  gint max_msg = 16 + data[1] * 8;
  gint rec_size = 1 + (data[2] & 0x3f);
  gsize chunk = (data[2] >> 6) ? (gsize) (data[2] >> 6) * 7 : G_MAXSIZE;
  data += 3;
  size -= 3;

  LogProtoServerOptionsStorage options;
  memset(&options, 0, sizeof(options));
  log_proto_server_options_defaults(&options);
  options.super.max_msg_size = max_msg;
  log_proto_server_options_init(&options, cfg);

  MemTransport *t = g_new0(MemTransport, 1);
  log_transport_init_instance(&t->super, "mem", -1);
  t->super.read = mem_transport_read;
  t->super.write = mem_transport_write;
  t->data = data;
  t->len = size;
  t->chunk = chunk;

  LogProtoServer *proto;
  switch (proto_sel)
    {
    case 0:
      proto = log_proto_framed_server_new(&t->super, &options);
      break;
    case 1:
      proto = log_proto_text_server_new(&t->super, &options);
      break;
    case 2:
      proto = log_proto_dgram_server_new(&t->super, &options);
      break;
    case 3:
      proto = log_proto_auto_server_new(&t->super, &options);
      break;
    case 4:
      proto = log_proto_binary_record_server_new(&t->super, &options, rec_size);
      break;
    default:
      proto = log_proto_padded_record_server_new(&t->super, &options, rec_size);
      break;
    }

  if (!log_proto_server_validate_options(proto))
    {
      log_proto_server_free(proto);
      log_proto_server_options_destroy(&options);
      return -1;
    }

  gboolean handshake_finished = FALSE;
  for (int i = 0; i < 16 && !handshake_finished; i++)
    {
      LogProtoServer *replacement = NULL;
      LogProtoStatus status = log_proto_server_handshake(proto, &handshake_finished, &replacement);
      if (replacement)
        {
          log_transport_stack_move(&replacement->transport_stack, &proto->transport_stack);
          log_proto_server_free(proto);
          proto = replacement;
        }
      if (status != LPS_SUCCESS && status != LPS_AGAIN)
        break;
    }

  for (int i = 0; handshake_finished && i < 4096; i++)
    {
      const guchar *msg = NULL;
      gsize msg_len = 0;
      gboolean may_read = TRUE;
      Bookmark bookmark;
      LogTransportAuxData aux;
      log_transport_aux_data_init(&aux);

      LogProtoStatus status = log_proto_server_fetch(proto, &msg, &msg_len, &may_read, &aux, &bookmark);
      log_transport_aux_data_destroy(&aux);
      if (status != LPS_SUCCESS && status != LPS_AGAIN)
        break;
      if (msg == NULL && !may_read)
        break;
    }

  log_proto_server_free(proto);
  log_proto_server_options_destroy(&options);
  scratch_buffers_explicit_gc();
  return 0;
}
