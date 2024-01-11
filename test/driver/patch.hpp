#include "common.hpp"

namespace framework {
class patch
{
    private:
        char*         image_name;
        void*         image_base;
        void*         patch_address;
        void*         original_bytes;
        unsigned long patch_size;

    public:
        patch(char* image_name);
        ~patch();
};
}