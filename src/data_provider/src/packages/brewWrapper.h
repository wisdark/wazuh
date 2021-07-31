/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BREW_WRAPPER_H
#define _BREW_WRAPPER_H

#include "ipackageWrapper.h"
#include "sharedDefs.h"
#include "stringHelper.h"
#include "filesystemHelper.h"

class BrewWrapper final : public IPackageWrapper
{
    public:
        explicit BrewWrapper(const PackageContext& ctx)
            : m_name{ctx.package}
            , m_version{Utils::splitIndex(ctx.version, '_', 0)}
            , m_format{"pkg"}
            , m_source{"homebrew"}
            , m_location{ctx.filePath}
        {
            const auto rows { Utils::split(Utils::getFileContent(ctx.filePath + "/" + ctx.package + "/" + ctx.version + "/.brew/" + ctx.package + ".rb"), '\n')};

            for (const auto& row : rows)
            {
                auto rowParsed { Utils::trim(row) };

                if (Utils::startsWith(rowParsed, "desc "))
                {
                    Utils::replaceFirst(rowParsed, "desc ", "");
                    Utils::replaceAll(rowParsed, "\"", "");
                    m_description = rowParsed;
                    break;
                }
            }
        }

        ~BrewWrapper() = default;

        std::string name() const override
        {
            return m_name;
        }
        std::string version() const override
        {
            return m_version;
        }
        std::string groups() const override
        {
            return m_groups;
        }
        std::string description() const override
        {
            return m_description;
        }
        std::string architecture() const override
        {
            return m_architecture;
        }
        std::string format() const override
        {
            return m_format;
        }
        std::string osPatch() const override
        {
            return m_osPatch;
        }
        std::string source() const override
        {
            return m_source;
        }
        std::string location() const override
        {
            return m_location;
        }

    private:
        std::string m_name;
        std::string m_version;
        std::string m_groups;
        std::string m_description;
        std::string m_architecture;
        const std::string m_format;
        std::string m_osPatch;
        const std::string m_source;
        const std::string m_location;
};


#endif //_BREW_WRAPPER_H