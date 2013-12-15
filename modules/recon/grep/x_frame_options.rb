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

# Check for lack of X-FRAME-OPTIONS header.
#
# @author Iain Funnell/yowie @iainfunnell
#
# @version 0.1.1
#
class Arachni::Modules::XFrameOptions < Arachni::Module::Base

    def run
      spider.on_each_page do |page|
        print_status "test: #{page.url}"
      end  
      #page.headers.each do |header|
        #  binding.pry

           # next if cookie.http_only? || audited?( cookie.name )

           # log( var: cookie.name, element: cookie.type, )
          #  audited( cookie.name )
        #end
    end


    def self.info
        {
            name:        'X-FRAME-OPTIONS headers',
            description: %q{Logs pages that do not set the X-FRAME-OPTIONS headers},
            elements:    [ Element::HEADER ],
            author:      'Iain "yowie" Funnell @iainfunnell',
            version:     '0.1.1',
            targets:     %w(Generic),
            references:  {
                'ClickJacking - OWASP' => 'https://www.owasp.org/index.php/ClickJacking'
            },
            issue:       {
                name:            %q{HttpOnly cookie},
                description:     %q{The logged cookie does not have the HttpOnly
    flag set which makes it succeptible to maniplation via client-side code.},
                cwe:             '200',
                severity:        Severity::INFORMATIONAL,
                remedy_guidance: %q{blerg},
            },
            max_issues: 1
        }
    end

end
