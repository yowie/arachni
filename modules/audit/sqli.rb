=begin
    Copyright 2010-2012 Tasos Laskos <tasos.laskos@gmail.com>

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
# SQL Injection audit module
#
# @author Tasos "Zapotek" Laskos <tasos.laskos@gmail.com>
#
# @version 0.1.6
#
# @see http://cwe.mitre.org/data/definitions/89.html
# @see http://unixwiz.net/techtips/sql-injection.html
# @see http://en.wikipedia.org/wiki/SQL_injection
# @see http://www.securiteam.com/securityreviews/5DP0N1P76E.html
# @see http://www.owasp.org/index.php/SQL_Injection
#
class Arachni::Modules::SQLInjection < Arachni::Module::Base

    def self.error_patterns
        @error_patterns ||= []
        if @error_patterns.empty?
            read_file( 'regexp_ids.txt' ) { |regexp| @error_patterns << regexp }
        end
        @error_patterns
    end

    def self.ignore_patterns
        @ignore_patterns ||= []
        if @ignore_patterns.empty?
            read_file( 'regexp_ignore.txt' ) { |regexp| @ignore_patterns << regexp }
        end
        @ignore_patterns
    end

    # Prepares the string that will hopefully cause the webapp
    # to output SQL error messages.
    def self.variations
        @variations ||= [ '\'`--', ')' ]
    end

    def self.opts
        @opts ||= {
            format:     [Format::APPEND],
            regexp:     error_patterns,
            ignore:     ignore_patterns,
            param_flip: true
        }
    end

    def run
        self.class.variations.each { |str| audit( str, self.class.opts ) }
    end

    def self.info
        {
            name:        'SQLInjection',
            description: %q{SQL injection recon module},
            elements:    [Element::LINK, Element::FORM, Element::COOKIE, Element::HEADER],
            author:      'Tasos "Zapotek" Laskos <tasos.laskos@gmail.com> ',
            version:     '0.1.6',
            references:  {
                'UnixWiz'    => 'http://unixwiz.net/techtips/sql-injection.html',
                'Wikipedia'  => 'http://en.wikipedia.org/wiki/SQL_injection',
                'SecuriTeam' => 'http://www.securiteam.com/securityreviews/5DP0N1P76E.html',
                'OWASP'      => 'http://www.owasp.org/index.php/SQL_Injection'
            },
            targets:     %w(Oracle ColdFusion InterBase PostgreSQL MySQL MSSql EMC SQLite DB2 Informix),
            issue:       {
                name:            %q{SQL Injection},
                description:     %q{SQL code can be injected into the web application.},
                tags:            %w(sql injection regexp database error),
                cwe:             '89',
                severity:        Severity::HIGH,
                cvssv2:          '9.0',
                remedy_guidance: 'User inputs must be validated and filtered
    before being included in database queries.',
                remedy_code:     '',
                metasploitable:  'unix/webapp/arachni_sqlmap'
            }
        }
    end

end
