#include "collector.h"
#include "catalog_generated.h"
#define DECLARE(id,fn) void fn(void);
COLLECTOR_REGISTRY(DECLARE)
#undef DECLARE
struct collector_entry {const char *id; void (*run)(void);};
#define ENTRY(id,fn) {id,fn},
static const struct collector_entry entries[]={COLLECTOR_REGISTRY(ENTRY)};
#undef ENTRY
int collector_allowed(const char *id) {
 for(size_t i=0;i<sizeof(entries)/sizeof(entries[0]);i++)
  if(!strcmp(id,entries[i].id))return 1;
 return 0;
}
void collect(const char *id) {
 used=0;overflow=0;
 for(size_t i=0;i<sizeof(entries)/sizeof(entries[0]);i++) {
  if(!strcmp(id,entries[i].id)) {
   entries[i].run();
   if(overflow)error_result("output_limit",0);
   return;
  }
 }
 error_result("collector_not_allowed",0);
}
