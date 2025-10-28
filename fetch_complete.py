import requests
import tmdbsimple as tmdb
import os
from dotenv import load_dotenv
import argparse
import hashlib
from flask import jsonify
import json

class RetrieveProviders():
    def __init__(self):
        load_dotenv()
        tmdb.API_KEY=os.getenv("API_KEY")
        print("supp")
        # print(os.getenv("API_KEY"))
        

    

    def hash_to_bucket(self, text: str, nonce: str, buckets: int = 5) -> int:
        """
        Hashes the text with a nonce and maps it into a range [0, buckets-1].
        
        Args:
            text (str): Input text.
            nonce (str): Nonce or salt to make the hash unique.
            buckets (int): Number of output buckets (default=5).
        
        Returns:
            int: Value in the range [0, buckets-1].
        """
        # Combine text and nonce

        combined = text + nonce

        # Hash using SHA256
        hash_bytes = hashlib.sha256(combined.encode('utf-8')).digest()

        # Convert bytes to integers and sum them
        total = sum(hash_bytes)

        # Map to range [0, buckets-1]
        return total % buckets



    
    def get_provider(self, movie_id, region='IN'):
        movie = tmdb.Movies(movie_id)
        movie.info()
        providers = movie.watch_providers()['results']
        provider_names=[]
        # print(providers)
        if not providers:
            # print("Movie not found")
            return ""
        if region not in providers:
            return ""
        # results = providers['results']
        if 'flatrate' in providers[region].keys():
            for fr in providers[region]['flatrate']:
                provider_names.append(fr['provider_name'])
        if 'rent' in providers[region].keys():
            for rt in providers[region]['rent']:
                provider_names.append(rt['provider_name']+" (rent)")
        # print(movie.title)
        if not provider_names:
            print("Providers not found")
        else:
            # print(provider_names)
            pass
        return provider_names
    
    def query(self, name):
        print("i am in query")
        search = tmdb.Search()
        print("i initialized searching")
        response = search.movie(query=name)
        # print("i reached query")
        # print(response)
        print("i finished searching")
        return response
    
    def search(self, movi):
        # query = request.args.get("query")
        # if not query:
            # return jsonify({"results": []})
        print("i reached here")
        results = self.query(movi)
        print("yoyoyoyoyoyo\n\n\n\n")
        movies = {}
        for result in results['results']:
            # movies=[]
            # movies['title'] = result['original_title']
            # print(f"movie:{movie}\n")
            title = str(result['original_title'])
            print(1)
            providers = self.get_provider(int(result['id']))
            providers_list = []
            movie = {}
            print(2)
            for provider in providers:
                movie = {}
                movie['provider'] = provider
                movie['resolution'] = self.hash_to_bucket(title, provider)
                movie['frame_rate'] = self.hash_to_bucket(title, "suppp"+provider)
                movie['region_latency'] = self.hash_to_bucket(title, "anotherone"+provider, 3)
                movie['adaptive_streaming'] = self.hash_to_bucket(title, "refraction"+provider, 2)
                movie['buffer_strategy'] = self.hash_to_bucket(title, "bufff"+provider, 3)
                # movie['providers'] = self.get_provider(int(result['id']))
                # print(movie)
                providers_list.append(movie)
            # temp = {}
            # temp[title] = providers_list
            movies[title] = providers_list
            # print(f"movies: {movies}")
        # print(f"movies: {movies}")
        return json.dumps(movies)

if __name__=="__main__":
    retriever = RetrieveProviders()
    parser = argparse.ArgumentParser()
    parser.add_argument("--movie_id", default="")
    parser.add_argument("--movie_name", default="")

    args = parser.parse_args()

    if args.movie_id:
        retriever.get_provider(args.movie_id)

    if args.movie_name:
        print(retriever.search(args.movie_name))

'''
    def search(self, movi):
        # query = request.args.get("query")
        # if not query:
            # return jsonify({"results": []})
        results = self.query(movi)
        print("yoyoyoyoyoyo\n\n\n\n")
        movies = []
        for result in results['results']:
            # movies=[]
            # movies['title'] = result['original_title']
            # print(f"movie:{movie}\n")
            title = str(result['original_title'])
            providers = self.get_provider(int(result['id']))
            providers_list = []
            movie = {}
            for provider in providers:
                movie = {}
                movie['provider'] = provider
                movie['resolution'] = self.hash_to_bucket(title, provider)
                movie['frame_rate'] = self.hash_to_bucket(title, "suppp"+provider)
                movie['region_latency'] = self.hash_to_bucket(title, "anotherone"+provider, 3)
                movie['adaptive_streaming'] = self.hash_to_bucket(title, "refraction"+provider, 2)
                movie['buffer_strategy'] = self.hash_to_bucket(title, "bufff"+provider, 3)
                # movie['providers'] = self.get_provider(int(result['id']))
                # print(movie)
                providers_list.append(movie)
            temp = {}
            temp[title] = providers_list
            movies.append(temp)
            # print(f"movies: {movies}")
        # print(f"movies: {movies}")
        return json.dumps(movies)
'''