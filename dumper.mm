#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <thread>
#include <chrono>
#include <vector>

void DumpDecryptedMetadata() {
    std::this_thread::sleep_for(std::chrono::seconds(8));

    mach_port_t task = mach_task_self();
    vm_address_t address = 0;
    vm_size_t size = 0;
    uint32_t depth = 1;

    const size_t targetDumpSize = 41279900; 
    const uint32_t unityMagic = 0xFAB11BAF; // AF 1B B1 FA

    while (true) {
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kern_return_t kr = vm_region_recurse_64(
            task, &address, &size, &depth,
            (vm_region_recurse_info_t)&info, &count
        );

        if (kr != KERN_SUCCESS) break;

        if (info.is_submap) {
            depth++;
            continue;
        }

        if ((info.protection & VM_PROT_READ) && size >= targetDumpSize) {
            uint32_t headerMagic = 0;
            vm_size_t outSize = 0;

            if (vm_read_overwrite(task, address, sizeof(uint32_t), (vm_address_t)&headerMagic, &outSize) == KERN_SUCCESS) {
                if (headerMagic == unityMagic) {
                    std::vector<uint8_t> buffer(targetDumpSize);
                    vm_size_t dumpOutSize = 0;

                    if (vm_read_overwrite(task, address, targetDumpSize, (vm_address_t)buffer.data(), &dumpOutSize) == KERN_SUCCESS && dumpOutSize == targetDumpSize) {
                        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
                        NSString *docDir = [paths firstObject];
                        NSString *filePath = [docDir stringByAppendingPathComponent:@"global-metadata-decrypted.dat"];

                        NSData *data = [NSData dataWithBytes:buffer.data() length:targetDumpSize];
                        [data writeToFile:filePath atomically:YES];
                        break;
                    }
                }
            }
        }
        address += size;
    }
}

__attribute__((constructor))
void InitDumper() {
    std::thread(DumpDecryptedMetadata).detach();
}
