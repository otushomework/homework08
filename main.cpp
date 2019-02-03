#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/regex.hpp>

#include <boost/crc.hpp>
#include <sodium.h>

#define CRC32 "crc32"
#define SODIUM "sodium"

//#define _DEBUG

namespace po = boost::program_options;
namespace fs = boost::filesystem;

static inline void trim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                    std::not1(std::ptr_fun<int, int>(std::isspace))));
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
}

void scanDir(const fs::path dirPath, std::list<fs::path> &fileList, const int level, const std::list<fs::path> &excludeDirs, const std::string &fmask, const int minFSize)
{
    const boost::regex fileMask( fmask );

    fs::directory_iterator it{dirPath};
    while (it != fs::directory_iterator{})
    {
        if (fs::is_symlink(*it))
        {
            *it++;
            continue;
        }

        bool foundExcluded = (std::find(excludeDirs.begin(), excludeDirs.end(), *it) != excludeDirs.end());
        if (level == 1 && fs::is_directory(*it))
        {
            if (!foundExcluded)
                scanDir(*it, fileList, level, excludeDirs, fmask, minFSize);
        }

        if (fs::is_regular_file(*it))
        {
            boost::smatch what;

            if ( fmask.length() != 0
                 && boost::regex_match( static_cast<fs::path>(*it).filename().string(), what, fileMask )
                 && fs::file_size(*it) >= minFSize )
                fileList.push_back(*it);
        }
        *it++;
    }
}

unsigned char getHash(char *buffer, const std::string &hashType, const int blockSize, const int lastReadBlockSize)
{
    if (lastReadBlockSize < blockSize)
        for (int i = blockSize - 1; i > blockSize - lastReadBlockSize; --i)
            buffer[i] = 0; //or '0' ?

    if (hashType == CRC32)
    {
        boost::crc_32_type result;
        result.process_bytes(buffer, sizeof(buffer));
        return result.checksum();
    }
    else if (hashType == SODIUM)
    {
        //https://libsodium.gitbook.io/doc/hashing/generic_hashing
        unsigned char hash[crypto_generichash_BYTES];

        int result = crypto_generichash(hash, sizeof hash,
                                        reinterpret_cast<unsigned char*>(buffer), sizeof(buffer),
                                        NULL, 0);

        return reinterpret_cast<unsigned char>(*hash);
    }

    return char();
}

//$ bayan
int main(int argc, const char *argv[])
{
    //https://libsodium.gitbook.io/doc/usage
    if (sodium_init() == -1) {
        return 1;
    }

    po::options_description desc{"Options"};
#ifdef _DEBUG
    desc.add_options()
            ("help,h", "This screen")
            ("scandirs", po::value<std::string>()->default_value("./testdata1,./testdata2"), "Directories for scan")
            ("excldirs", po::value<std::string>()->default_value("./testdata1/exclude,./testdata2/exclude"), "Directories for exclude")
            ("level", po::value<int>()->default_value(1), "Scan level: 1 - with subdirs, 0 - only current")
            ("minfsize", po::value<int>()->default_value(1), "Minimal file size in bytes")
            ("fmask", po::value<std::string>()->default_value(".*\\.txt"), "File mask for scan")
            ("blocksize", po::value<int>()->default_value(5), "Reading block size, in bytes")
            ("hashtype", po::value<std::string>()->default_value(SODIUM), "Hash algorithm type (sodium or crc32)");
#else
    desc.add_options()
            ("help,h", "This screen")
            ("scandirs", po::value<std::string>(), "Directories for scan")
            ("excldirs", po::value<std::string>(), "Directories for exclude")
            ("level", po::value<int>()->default_value(1), "Scan level: 1 - with subdirs, 0 - only current")
            ("minfsize", po::value<int>()->default_value(1), "Minimal file size in bytes")
            ("fmask", po::value<std::string>()->default_value(".*\\.txt"), "File mask for scan")
            ("blocksize", po::value<int>()->default_value(5), "Reading block size, in bytes")
            ("hashtype", po::value<std::string>()->default_value(SODIUM), "Hash algorithm type (sodium or crc32)");
#endif

    po::variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if (vm.count("help") || !vm.count("scandirs"))
    {
        std::cout << desc << std::endl;
        return 0;
    }

    //validate some input params
    if (vm["hashtype"].as<std::string>() != CRC32
            && vm["hashtype"].as<std::string>() != SODIUM)
    {
        std::cout << "Wrong hash type" << std::endl;
        std::cout << desc << std::endl;
        return 1;
    }

    std::list<fs::path> scanDirs;
    std::list<fs::path> excludeDirs;

    boost::tokenizer<boost::char_separator<char>> scanDirsTokenizer{vm["scandirs"].as<std::string>(), boost::char_separator<char>{","}};
    for (auto line: scanDirsTokenizer)
    {
        trim(line);
        scanDirs.push_back(fs::canonical(line));
    }

    if (!vm["excldirs"].empty())
    {
        boost::tokenizer<boost::char_separator<char>> exclDirsTokenizer{vm["excldirs"].as<std::string>(), boost::char_separator<char>{","}};
        for (auto line: exclDirsTokenizer)
        {
            trim(line);
            excludeDirs.push_back(fs::canonical(line));
        }
    }

    std::list<fs::path> fullScanFileList;
    for (auto dir: scanDirs)
    {
        scanDir(dir, fullScanFileList,
                vm["level"].as<int>(),
                excludeDirs,
                vm["fmask"].as<std::string>(),
                vm["minfsize"].as<int>());
    }

    std::vector<fs::path> foundDuplicates;

    for (auto testFile: fullScanFileList)
    {
        std::vector<unsigned char> testFileHashes;
        std::ifstream testFileStream(testFile.string(), std::ios::binary);
        char testFileBuffer[vm["blocksize"].as<int>()];

        bool foundInDuplicates = (std::find(foundDuplicates.begin(), foundDuplicates.end(), testFile) != foundDuplicates.end());
        if (foundInDuplicates)
        {
            std::cout << "Skip duplicate file: " << testFile.string() << std::endl;
            continue;
        }

        std::cout << "Check file: " << testFile.string() << ":" << std::endl;

        for (auto subTestFile: fullScanFileList)
        {
            if (testFile == subTestFile)
                continue;

            std::vector<unsigned char> subTestFileHashes;
            std::ifstream subTestFileStream(subTestFile.string(), std::ios::binary);
            char subTestFileBuffer[vm["blocksize"].as<int>()];

            bool diffFound = false;
            while (subTestFileStream.get(subTestFileBuffer, vm["blocksize"].as<int>()) || subTestFileStream.gcount())
            {
                subTestFileHashes.push_back(getHash(subTestFileBuffer, vm["hashtype"].as<std::string>(), vm["blocksize"].as<int>(), subTestFileStream.gcount()));
                //std::cout << subTestFileBuffer << std::endl;
                if (subTestFileHashes.size() > testFileHashes.size())
                {
                    testFileStream.get(testFileBuffer, vm["blocksize"].as<int>());
                    //std::cout << testFileBuffer << std::endl;
                    testFileHashes.push_back(getHash(testFileBuffer, vm["hashtype"].as<std::string>(), vm["blocksize"].as<int>(), testFileStream.gcount()));
                }

                if (subTestFileHashes[subTestFileHashes.size()-1] != testFileHashes[subTestFileHashes.size()-1])
                {
                    diffFound = true;
                }
            }

            if (!diffFound)
            {
                std::cout << " - " << subTestFile.string() << std::endl;
                foundDuplicates.push_back(subTestFile);
            }
        }
    }

    return 0;
}
