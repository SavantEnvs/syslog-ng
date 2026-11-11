/* Fuzzes the patterndb radix tree: a fixed tree of patterns covering every parser type is
 * searched with the fuzzed key; when the input holds a newline, the text before it is also
 * inserted as an extra pattern (exercising pattern compilation) and the text after it is the key. */
#include "apphook.h"
#include "messages.h"
#include "logmsg/logmsg.h"
#include "radix.h"
#include "scratch-buffers.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

static void
drop_message(LogMessage *msg)
{
  log_msg_unref(msg);
}

static const char *const patterns[] =
{
  "foo bar baz",
  "foo @NUMBER:n@ bar",
  "@ESTRING:host: @login: @STRING:user@ from @IPv4:ip@",
  "sshd: Accepted @ESTRING:method: @for @QSTRING:u:\"@ from @IPv6:ip6@",
  "@FLOAT:f@ @HOSTNAME:h@ @EMAIL:mail@ @MACADDR:mac@",
  "msg @SET:s: abc@ @ANYSTRING:rest@",
  "@NLSTRING:line@\n",
  "id=@NUMBER:id@ ip=@IPvANY:ip@ pcre=@PCRE:pc:[a-z]+[0-9]*@ x",
  "@LLADDR:l@ @STRING:str:@",
  "@ESTRING:path:/@@ESTRING:file: @end",
  "foo @NUMBER:n:@ fox",
  "@ANYSTRING:a@",
};

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
  if (size == 0 || size > 4096)
    return -1;

  RNode *root = r_new_node("", NULL);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    {
      gchar *dup = g_strdup(patterns[i]);
      r_insert_node(root, dup, (gpointer) patterns[i], NULL, NULL, NULL);
      g_free(dup);
    }

  const uint8_t *key = data;
  size_t key_len = size;
  const uint8_t *nl = memchr(data, '\n', size);
  if (nl && nl != data + size - 1)
    {
      gchar *extra = g_strndup((const gchar *) data, nl - data);
      r_insert_node(root, extra, extra, NULL, NULL, NULL);
      g_free(extra);
      key = nl + 1;
      key_len = size - (key - data);
    }

  gchar *k = g_strndup((const gchar *) key, key_len);
  GArray *matches = g_array_new(FALSE, TRUE, sizeof(RParserMatch));
  g_array_set_size(matches, 1);
  r_find_node(root, k, key_len, matches);
  for (gsize i = 0; i < matches->len; i++)
    g_free(g_array_index(matches, RParserMatch, i).match);
  g_array_free(matches, TRUE);
  g_free(k);

  r_free_node(root, NULL);
  scratch_buffers_explicit_gc();
  return 0;
}
