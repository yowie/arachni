require 'sinatra'
require 'sinatra/contrib'

get '/' do
    response.headers['Cache-Control'] = 'public, max-age=300'
end
