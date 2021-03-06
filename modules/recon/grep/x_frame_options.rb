=begin
    Copyright 2010-2013 Tasos Laskos <tasos.laskos@gmail.com>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
=end

#
# Looks for and logs missing framing protection.
#
# @author Iain "yowie" Funnell <iainfunnell@gmail.com>
#
# @version 0.1.1

class Arachni::Modules::XFrameOptions < Arachni::Module::Base

    def run
        unless audited?(extract_domain(page.url))
            unless page.response_headers.has_key?("X-Frame-Options")
              log( var: extract_domain(page.url), match: page.response_headers,
                  element: Element::SERVER)
            end
            audited( extract_domain(page.url))
        end
    end


    def self.info
        {
            name:        'Lack of ClickJacking protection (X-FRAMES-OPTIONS headers)',
            description: %q{Logs servers that do not set the X-FRAME-OPTIONS headers},
            elements:    [ Element::SERVER ],
            author:      'Iain "yowie" Funnell <@iainfunnell> <iainfunnell@gmail.com',
            version:     '0.1.1',
            targets:     %w(Generic),
            references:  {
                'ClickJacking - OWASP' => 'https://www.owasp.org/index.php/ClickJacking'
            },
            issue:       {
                name:            %q{Lack of ClickJacking Protection},
                description:     %q{The server does not adequately protect the page from framing attacks},
                cwe:              '200',
                severity:        Severity::INFORMATIONAL,
                remedy_guidance: %q{The server should include the X-Frame-Options header 
                    to prevent the site from being loaded in a malicious frame.}
            },
            #max_issues: 1
        }
    end

end
