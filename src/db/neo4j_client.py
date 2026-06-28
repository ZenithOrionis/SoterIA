import logging
from neo4j import GraphDatabase
from src.config.settings import get_settings

logger = logging.getLogger("aegis.neo4j")
settings = get_settings()

class Neo4jClient:
    def __init__(self):
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = settings.NEO4J_PASS
        self.driver = None

    def connect(self):
        if not self.driver:
            try:
                self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
                logger.info(f"Connected to Neo4j at {self.uri}")
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def check_blast_radius(self, username: str) -> dict:
        """
        Query Neo4j to see if the user has a path to High-Value Targets (e.g. Domain Admins).
        Returns a dict with path info if found, or None.
        """
        if not self.driver:
            self.connect()
        if not self.driver:
            return None
            
        # Simple query: Can this user reach Domain Admins within 3 hops?
        query = """
        MATCH p = (u:User)-[*1..3]->(g:Group)
        WHERE u.name =~ '(?i).*' + $username + '.*' 
          AND g.objectid ENDS WITH '-512'
        RETURN u.name AS user, g.name AS target, length(p) as hops
        LIMIT 1
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, username=username)
                record = result.single()
                if record:
                    return {
                        "user": record["user"],
                        "target": record["target"],
                        "hops": record["hops"]
                    }
        except Exception as e:
            logger.error(f"Neo4j Query Error: {e}")
        return None

# Singleton instance
neo4j_client = Neo4jClient()
