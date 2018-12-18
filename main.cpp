#include <iostream>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/regex.hpp>

#include <boost/uuid/detail/md5.hpp>
#include <boost/uuid/detail/sha1.hpp>
#include <boost/crc.hpp>

#define MD5 "md5"
#define SHA1 "sha1"
#define CRC32 "crc32"

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

std::string getHash(char *buffer, const std::string &hashType, const int blockSize, const int lastReadBlockSize)
{
    //fill readed block
    if (lastReadBlockSize < blockSize)
        for (int i = blockSize - 1; i > blockSize - lastReadBlockSize; --i)
            buffer[i] = 0; //or '0' ?

    if (hashType == CRC32)
    {
        boost::crc_32_type result;
        result.process_bytes(buffer, sizeof(buffer));
        return std::to_string(result.checksum());
    }
    else if (hashType == MD5)
    {
        boost::uuids::detail::md5 md5;
        md5.process_bytes(buffer, sizeof(buffer));
        unsigned int hash[4] = {0};
        md5.get_digest(hash);

        char buf[41] = {0};
        for (int i = 0; i < 4; i++)
        {
            std::sprintf(buf + (i << 3), "%08x", hash[i]);
        }

        //std::cout << std::string(buf) << std::endl;
        return std::string(buf);
    }
    else if (hashType == SHA1)
    {
        boost::uuids::detail::sha1 sha1;
        sha1.process_bytes(buffer, sizeof(buffer));
        unsigned hash[5] = {0};
        sha1.get_digest(hash);

        char buf[41] = {0};
        for (int i = 0; i < 5; i++)
        {
            std::sprintf(buf + (i << 3), "%08x", hash[i]);
        }

        //std::cout << std::string(buf) << std::endl;
        return std::string(buf);
    }

    return std::string();
}

//$ bayan
int main(int argc, const char *argv[])
{
    po::options_description desc{"Options"};
    desc.add_options()
            ("help,h", "This screen")
            ("scandirs", po::value<std::string>()->default_value("./testdata1,./testdata2"), "Directories for scan")
            ("excldirs", po::value<std::string>()->default_value("./testdata1/exclude,./testdata2/exclude"), "Directories for exclude")
            ("level", po::value<int>()->default_value(1), "Scan level: 1 - with subdirs, 0 - only current")
            ("minfsize", po::value<int>()->default_value(1), "Minimal file size in bytes")
            ("fmask", po::value<std::string>()->default_value(".*\\.txt"), "File mask for scan")
            ("blocksize", po::value<int>()->default_value(5), "Reading block size, in bytes")
            ("hashtype", po::value<std::string>()->default_value(CRC32), "Hash algorithm type (md5, sha1 or crc32)");

    po::variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if (vm.count("help"))
    {
        std::cout << desc << std::endl;
        return 0;
    }

    //validate some input params
    if (vm["hashtype"].as<std::string>() != CRC32
            && vm["hashtype"].as<std::string>() != MD5
            && vm["hashtype"].as<std::string>() != SHA1)
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

    boost::tokenizer<boost::char_separator<char>> exclDirsTokenizer{vm["excldirs"].as<std::string>(), boost::char_separator<char>{","}};
    for (auto line: exclDirsTokenizer)
    {
        trim(line);
        excludeDirs.push_back(fs::canonical(line));
    }

    std::list<fs::path> fullScanFileList;
    for (auto dir: scanDirs)
    {
        scanDir(dir, fullScanFileList, vm["level"].as<int>(), excludeDirs, vm["fmask"].as<std::string>(), vm["minfsize"].as<int>());
    }

    std::vector<fs::path> foundDuplicates;

    for (auto testFile: fullScanFileList)
    {
        std::vector<std::string> testFileHashes;
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

            std::vector<std::string> subTestFileHashes;
            std::ifstream subTestFileStream(subTestFile.string(), std::ios::binary);
            char subTestFileBuffer[vm["blocksize"].as<int>()];

            bool diffFound = false;
            while (subTestFileStream.read(subTestFileBuffer, sizeof(subTestFileBuffer)) || subTestFileStream.gcount())
            {
                subTestFileHashes.push_back(getHash(subTestFileBuffer, vm["hashtype"].as<std::string>(), vm["blocksize"].as<int>(), subTestFileStream.gcount()));

                if (subTestFileHashes.size() > testFileHashes.size())
                {
                    testFileStream.read(testFileBuffer, sizeof(testFileBuffer));
                    testFileHashes.push_back(getHash(testFileBuffer, vm["hashtype"].as<std::string>(), vm["blocksize"].as<int>(), testFileStream.gcount()));
                }

                if (subTestFileHashes[subTestFileHashes.size()-1] != testFileHashes[subTestFileHashes.size()-1])
                {
                    diffFound = true;
                    //std::cout << "Difference detected " << testFile.string() << " != " << subTestFile.string() << std::endl;
                }

                //std::cout << subTestFileBuffer << " -> " << subTestFileStream.gcount() << " -> " << result.checksum() << std::endl;
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
