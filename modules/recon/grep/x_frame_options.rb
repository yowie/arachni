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
# Check for lack of X-FRAME-OPTIONS header.
#
# @author Iain Funnell/yowie @iainfunnell
#
# @version 0.1.1
#
class Arachni::Modules::XFrameOptions < Arachni::Module::Base

    def run
        page.headers.each do |header|
           # next if cookie.http_only? || audited?( cookie.name )

           # log( var: cookie.name, element: cookie.type, )
          #  audited( cookie.name )
        end
    end

    def self.info
        {
            name: 'X-FRAME-OPTIONS check',
            description: %q{Checks if the X-FRAME-OPTIONS header is configured to prevent framing attacks.},
            elements: [ Element::HEADER ],
            author: 'Iain Funnell @iainfunnell',
            version: '0.1.1',
            targets: %w(Generic),
            references: {
                'ClickJacking - OWASP' => 'https://www.owasp.org/index.php/Clickjacking'
            ,}
            issue: {
                name: %q{X-FRAME-OPTIONS header missing},
                description: %q{The site has not enabled the X-FRAME-OPTIONS header 
                which makes it succeptible to ClickJacking/Framing attacks.},
                cwe: '200',
                severity: Severity::INFORMATIONAL,
                remedy_guidance: %q{Set the 'X-FRAME-OPTIONS' header in server responses.},
            }
        }
    end

end
