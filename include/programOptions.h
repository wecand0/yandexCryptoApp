#pragma once

#include <boost/program_options.hpp>

#include <format>
#include <print>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

namespace po = boost::program_options;

class ProgramOptions {
public:
    ProgramOptions();
    ProgramOptions(ProgramOptions &) = delete;
    ProgramOptions &operator=(const ProgramOptions &) = delete;
    ProgramOptions(ProgramOptions &&) = delete;
    ProgramOptions &operator=(ProgramOptions &&) = delete;
    ~ProgramOptions() = default;

    void Parse(int argc, char *argv[]);

    enum class COMMAND_TYPE { ENCRYPT, DECRYPT, CHECKSUM, HELP, UNKNOWN };

    bool IsHelpRequested() const;
    COMMAND_TYPE GetCommand() const;
    std::string GetInputPath() const;
    std::string GetOutputPath() const;
    std::string GetPassword() const;

private:


    // Маппинг строковых команд на enum
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {{"encrypt", COMMAND_TYPE::ENCRYPT},
                                                                                {"decrypt", COMMAND_TYPE::DECRYPT},
                                                                                {"checksum", COMMAND_TYPE::CHECKSUM},
                                                                                {"help", COMMAND_TYPE::HELP},
                                                                                {"unknown", COMMAND_TYPE::UNKNOWN}};
    COMMAND_TYPE MapStringToCommand(const std::string_view &cmd) const;
    void ValidateOptions() const;

    bool isHelp_{};
    COMMAND_TYPE command_ = COMMAND_TYPE::UNKNOWN;

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    po::variables_map vm_;
    po::options_description desc_;



};
}  // namespace CryptoGuard
